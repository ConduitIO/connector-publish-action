// Copyright © 2026 Meroxa, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command connector is a deliberately trivial stand-in for a real Conduit
// connector's cmd/connector binary, used ONLY by
// .github/workflows/e2e.yml's "build" job. It exists so that job can drive
// action.yml's mode=build step (cosign install, matrix build+digest+sign,
// gh release upload) against a real `go build` invocation across the
// default build-matrix's four (os, arch) cells, without depending on any
// actual connector repo. It intentionally does nothing at runtime — the
// e2e workflow only cares that a binary gets produced, signed, and
// uploaded; it never executes this binary.
package main

func main() {}
