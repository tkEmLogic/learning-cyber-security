package courseapp

// The console transport Tier 6 enrolls over.
//
// Settled on issue #113: enrollment runs over the board's USB serial console
// rather than over the network, because a Bootstrap credential delivered
// "through a channel separate from its normal network traffic" is not separate
// if enrollment is an HTTPS POST.
//
// Written against syscall directly, the way deviceReset already is, so the
// course keeps its one dependency.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	tcgets = 0x5401
	tcsets = 0x5402

	// Termios flags, spelled out rather than imported, because the whole
	// point of this file is that it adds no dependency.
	iflagOff = syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	lflagOff = syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN

	// The baud rate field inside Cflag. syscall does not export CBAUD on
	// Linux, and the value is part of the kernel ABI rather than something
	// this file gets to choose.
	cbaud = 0x100f
)

type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Ispeed uint32
	Ospeed uint32
}

// console is one open serial connection to the board.
type console struct {
	port    *os.File
	reader  *bufio.Reader
	restore termios
}

// openConsole puts the port in raw mode at 115200 and returns it.
//
// Raw matters more than the speed does. This is a USB CDC device, so the baud
// rate is cosmetic, but line discipline is not: with canonical mode left on,
// the kernel rewrites what the board sent before this code sees it.
func (a *app) openConsole() (*console, error) {
	device, err := a.selectSerialDevice()
	if err != nil {
		return nil, err
	}
	port, err := os.OpenFile(device, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", device, err)
	}

	var saved termios
	if err := ioctlTermios(port.Fd(), tcgets, &saved); err != nil {
		port.Close()
		return nil, err
	}
	raw := saved
	raw.Iflag &^= iflagOff
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= lflagOff
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB | cbaud
	raw.Cflag |= syscall.CS8 | syscall.CREAD | syscall.CLOCAL | syscall.B115200
	raw.Ispeed = syscall.B115200
	raw.Ospeed = syscall.B115200
	// VMIN 0 with VTIME 1 makes a read return after a tenth of a second even
	// when the board has said nothing, so a missing answer is a timeout
	// rather than a hang.
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 1
	if err := ioctlTermios(port.Fd(), tcsets, &raw); err != nil {
		port.Close()
		return nil, err
	}

	return &console{port: port, reader: bufio.NewReader(port), restore: saved}, nil
}

func (c *console) Close() error {
	_ = ioctlTermios(c.port.Fd(), tcsets, &c.restore)
	return c.port.Close()
}

func ioctlTermios(fd uintptr, request uintptr, t *termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request,
		uintptr(unsafe.Pointer(t))); errno != 0 {
		return fmt.Errorf("serial ioctl failed: %w", errno)
	}
	return nil
}

// send writes one command line.
//
// It is written in small pieces with a pause between them. The shell's serial
// receive ring is small and the shell thread does not drain it while the
// application is printing, and a line written in one go lost characters out of
// the middle of a credential. Nothing reported the loss: a dropped character is
// not an error, it is a different command. The fix on the device was a larger
// ring; the pacing here is the belt to that pair of braces, and it costs
// milliseconds.
func (c *console) send(line string) error {
	data := []byte(line + "\r\n")
	for offset := 0; offset < len(data); offset += 32 {
		end := offset + 32
		if end > len(data) {
			end = len(data)
		}
		if _, err := c.port.Write(data[offset:end]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// collect reads lines until done says stop, or until the deadline passes.
//
// Every line is returned, including the application's own printk output, which
// shares this console. Callers filter by prefix rather than assuming the board
// said only what they asked for.
func (c *console) collect(timeout time.Duration, done func(line string) bool) ([]string, error) {
	deadline := time.Now().Add(timeout)
	var lines []string
	var partial strings.Builder
	for time.Now().Before(deadline) {
		chunk, err := c.reader.ReadString('\n')
		if chunk != "" {
			partial.WriteString(chunk)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return lines, err
		}
		if !strings.HasSuffix(chunk, "\n") {
			continue
		}
		line := strings.TrimRight(partial.String(), "\r\n")
		partial.Reset()
		line = strings.TrimSpace(stripPrompt(line))
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if done != nil && done(line) {
			return lines, nil
		}
	}
	return lines, fmt.Errorf("the board said nothing more within %s", timeout)
}

// stripPrompt removes the shell prompt the board echoes before a line.
func stripPrompt(line string) string {
	if index := strings.LastIndex(line, "uart:~$ "); index >= 0 {
		return line[index+len("uart:~$ "):]
	}
	return line
}

// readChunked reads one of the board's begin/data/end hex transfers.
//
// The device prints its certification request and its certificate this way
// because neither fits a console line. The declared length is checked against
// what arrived, so a transfer that stopped early is an error here rather than
// a short structure that fails to parse a long way downstream.
func (c *console) readChunked(tag string, timeout time.Duration) ([]byte, error) {
	var hex strings.Builder
	declared := 0
	began := false
	var failure string

	_, err := c.collect(timeout, func(line string) bool {
		switch {
		case strings.HasPrefix(line, tag+" begin "):
			fmt.Sscanf(line, tag+" begin %d", &declared)
			began = true
		case began && strings.HasPrefix(line, tag+" data "):
			hex.WriteString(strings.TrimPrefix(line, tag+" data "))
		case began && line == tag+" end":
			return true
		case strings.Contains(line, "could not") || strings.Contains(line, "refused"):
			failure = line
			return true
		}
		return false
	})
	if failure != "" {
		return nil, errors.New(failure)
	}
	if err != nil {
		return nil, err
	}
	if !began {
		return nil, fmt.Errorf("the board printed no %s transfer", tag)
	}
	raw, err := decodeHex(hex.String())
	if err != nil {
		return nil, err
	}
	if len(raw) != declared {
		return nil, fmt.Errorf("the board declared %d bytes of %s and sent %d",
			declared, tag, len(raw))
	}
	return raw, nil
}

// sendChunked is the same transfer in the other direction.
func (c *console) sendChunked(command string, data []byte) error {
	if err := c.send(fmt.Sprintf("%s begin %d", command, len(data))); err != nil {
		return err
	}
	if _, err := c.collect(3*time.Second, func(line string) bool {
		return strings.Contains(line, "expecting") || strings.Contains(line, "out of range")
	}); err != nil {
		return err
	}
	const chunk = 32
	for offset := 0; offset < len(data); offset += chunk {
		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}
		if err := c.send(fmt.Sprintf("%s data %x", command, data[offset:end])); err != nil {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
	return c.send(command + " end")
}

func decodeHex(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if len(text)%2 != 0 {
		return nil, errors.New("the board sent an odd number of hex characters")
	}
	out := make([]byte, len(text)/2)
	for i := 0; i < len(out); i++ {
		var value int
		if _, err := fmt.Sscanf(text[i*2:i*2+2], "%02x", &value); err != nil {
			return nil, fmt.Errorf("the board sent something that is not hex: %w", err)
		}
		out[i] = byte(value)
	}
	return out, nil
}
