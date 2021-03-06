<!-- omit in toc -->
# go-nagios

Shared Golang package for Nagios plugins

[![Latest Release](https://img.shields.io/github/release/atc0005/go-nagios.svg?style=flat-square)](https://github.com/atc0005/go-nagios/releases/latest)
[![GoDoc](https://godoc.org/github.com/atc0005/go-nagios?status.svg)](https://godoc.org/github.com/atc0005/go-nagios)
[![Validate Codebase](https://github.com/atc0005/go-nagios/workflows/Validate%20Codebase/badge.svg)](https://github.com/atc0005/go-nagios/actions?query=workflow%3A%22Validate+Codebase%22)
[![Validate Docs](https://github.com/atc0005/go-nagios/workflows/Validate%20Docs/badge.svg)](https://github.com/atc0005/go-nagios/actions?query=workflow%3A%22Validate+Docs%22)
[![Lint and Build using Makefile](https://github.com/atc0005/go-nagios/workflows/Lint%20and%20Build%20using%20Makefile/badge.svg)](https://github.com/atc0005/go-nagios/actions?query=workflow%3A%22Lint+and+Build+using+Makefile%22)
[![Quick Validation](https://github.com/atc0005/go-nagios/workflows/Quick%20Validation/badge.svg)](https://github.com/atc0005/go-nagios/actions?query=workflow%3A%22Quick+Validation%22)

<!-- omit in toc -->
## Table of contents

- [Status](#status)
- [Overview](#overview)
- [Features](#features)
- [Changelog](#changelog)
- [Examples](#examples)
  - [Use only the provided constants](#use-only-the-provided-constants)
  - [Use `ReturnCheckResults` method](#use-returncheckresults-method)
  - [Use `ReturnCheckResults` method with a branding callback](#use-returncheckresults-method-with-a-branding-callback)
- [License](#license)
- [References](#references)

## Status

Alpha quality.

This codebase is subject to change without notice and may break client code
that depends on it. You are encouraged to [vendor](#references) this package
if you find it useful until such time that the API is considered stable.

## Overview

This package contains common types and package-level variables used when
developing Nagios plugins. The intent is to reduce code duplication between
various plugins and help reduce typos associated with literal strings.

## Features

- Nagios state constants
  - state labels (e.g., `StateOKLabel`)
  - state exit codes (e.g., `StateOKExitCode`)
- `ExitState` type with `ReturnCheckResults` method
  - used to process and return all applicable check results to Nagios for
    further processing/display
  - supports "branding" callback function to display application name,
    version, or other information as a "trailer" for check results provided to
    Nagios
    - this could be useful for identifying what version of a plugin determined
      the service or host state to be an issue
  - captures panics from client code
    - surfaces these panics as `CRITICAL` state and overrides service output
      and error details to make any panics prominent

## Changelog

See the [`CHANGELOG.md`](CHANGELOG.md) file for the changes associated with
each release of this application. Changes that have been merged to `master`,
but not yet an official release may also be noted in the file under the
`Unreleased` section. A helpful link to the Git commit history since the last
official release is also provided for further review.

## Examples

### Use only the provided constants

Assuming that you're using [Go
Modules](https://blog.golang.org/using-go-modules), add this line to your
imports like so:

```golang
package main

import (
  "fmt"
  "log"
  "os"

  "github.com/atc0005/go-nagios"
)
  ```

Then in your code, reference the data types as you would from any other
package:

```golang
fmt.Println("OK: All checks have passed")
os.Exit(nagios.StateOKExitCode)
```

Alternatively, you can also use the provided state "labels" (constants) to
avoid using literal string state values:

```golang
fmt.Printf("%s: All checks have passed\r\n", nagios.StateOKLabel)
os.Exit(nagios.StateOKExitCode)
```

When you next build your package this one should be pulled in.

### Use `ReturnCheckResults` method

Assuming that you're using [Go
Modules](https://blog.golang.org/using-go-modules), add this line to your
imports like so:

```golang
package main

import (
  "fmt"
  "log"
  "os"

  "github.com/atc0005/go-nagios"
)
```

then in your code, create an instance of `ExitState` and immediately defer
`ReturnCheckResults()`. If you don't, any other deferred functions *will not
run*.

Here we're optimistic and we are going to note that all went well.

```golang

    var nagiosExitState = nagios.ExitState{
        LastError:         nil,
        ExitStatusCode:    nagios.StateOKExitCode,
    }

    defer nagiosExitState.ReturnCheckResults()

    // more stuff here

    nagiosExitState.ServiceOutput = certs.OneLineCheckSummary(
        nagios.StateOKLabel,
        certChain,
        certsSummary.Summary,
    )

    nagiosExitState.LongServiceOutput := certs.GenerateCertsReport(
        certChain,
        certsExpireAgeCritical,
        certsExpireAgeWarning,
    )

```

For handling error cases, the approach is roughly the same, only you call
`return` explicitly to end execution of the client code and allow deferred
functions to run.

### Use `ReturnCheckResults` method with a branding callback

Assuming that you're using [Go
Modules](https://blog.golang.org/using-go-modules), add this line to your
imports like so:

```golang
package main

import (
  "fmt"
  "log"
  "os"
  "strings"

  "github.com/atc0005/go-nagios"
)
```

then in this example, we'll make a further assumption that you have a `config`
value with an `EmitBranding` field to indicate whether the user/sysadmin has
opted to emit branding information.

```golang
func main() {

    var nagiosExitState = nagios.ExitState{
        LastError:         nil,
        ExitStatusCode:    nagios.StateOKExitCode,
    }

    defer nagiosExitState.ReturnCheckResults()

    // ...

    if config.EmitBranding {
      // If enabled, show application details at end of notification
      nagiosExitState.BrandingCallback = Branding("Notification generated by ")
    }

    // ...

}
```

the `Branding` function might look something like this:

```golang
// Branding accepts a message and returns a function that concatenates that
// message with version information. This function is intended to be called as
// a final step before application exit after any other output has already
// been emitted.
func Branding(msg string) func() string {
    return func() string {
        return strings.Join([]string{msg, Version()}, "")
    }
}
```

but you could just as easily create an anonymous function as the callback:

```golang
func main() {

    var nagiosExitState = nagios.ExitState{
        LastError:         nil,
        ExitStatusCode:    nagios.StateOKExitCode,
    }

    defer nagiosExitState.ReturnCheckResults()

    if config.EmitBranding {
        // If enabled, show application details at end of notification
        nagiosExitState.BrandingCallback = func(msg string) func() string {
            return func() string {
                return "Notification generated by " + msg
            }
        }("HelloWorld")
    }

    // ...

}
```

## License

From the [LICENSE](LICENSE) file:

```license
MIT License

Copyright (c) 2020 Adam Chalkley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## References

- Nagios
  - <https://github.com/nagios-plugins/nagios-plugins/blob/master/plugins-scripts/utils.sh.in>
  - <http://nagios-plugins.org/doc/guidelines.html>
  - <https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/macrolist.html>
  - <https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/4/en/macrolist.html>
- Go Modules
  - <https://www.ardanlabs.com/blog/2020/04/modules-06-vendoring.html>
  - <https://github.com/golang/go/wiki/Modules>
- Panics, stack traces
  - <https://www.golangprograms.com/example-stack-and-caller-from-runtime-package.html>
