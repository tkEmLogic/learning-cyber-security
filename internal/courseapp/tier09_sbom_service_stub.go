package courseapp

import "errors"

// Replaced by the service SBOM when the scanning half of #277 lands.
func (a *app) sbomService(args []string) error {
	return errors.New("./course sbom service is not built yet")
}
