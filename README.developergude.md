## FAUCET developer guide

This file contains an overview of architecture, coding design/practices, testing and style.

### Before submitting a PR

* All unit tests must pass (please use the docker based tests; see README.docker.md).
* pylint must show no new errors or warnings.
* Code must conform to the style guide (see below).

### Code style

Please use the coding style documented at http://google.github.io/styleguide/pyguide.html. Existing
code not using this style will be incrementally migrated to comply with it. New code should comply.
