# Learning Cyber Security

This context defines the language used to design and teach the embedded and IoT
cybersecurity course.

## Language

**Course specification**:
The implementation-ready description of the course audience, architecture,
modules, labs, assessment, and supporting repository.
_Avoid_: Course plan, curriculum notes

**Learner**:
An embedded software engineer who has little or no experience applying
cybersecurity in an embedded product-development context.
_Avoid_: Student, beginner, new graduate

**Mentor**:
An experienced engineer who reviews the learner's work at defined points.
_Avoid_: Teacher, lecturer

**Mentor review gate**:
A scheduled review where the learner demonstrates a result, explains the
security reasoning, and responds to a prepared failure or challenge.
_Avoid_: Instructor checkpoint, lesson review

**Reference product**:
An industrial equipment status beacon built around an ESP32-C6. It shows a
simulated machine state with one monochrome LED. On means normal operation. Off
means the device is off. Fast and slow blinking show two fictional error states.
The device reports status over Wi-Fi and receives software updates over Wi-Fi.
_Avoid_: Demo app, blinky, access controller

**Lab artifact**:
A reviewable result that shows what the learner designed, implemented,
observed, or concluded during a lab.
_Avoid_: Homework, deliverable
