// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

// Covers are not files and not environment variables.
// The host records the approved process tree when that tree calls __seal,
// and a later catch is allowed only while the caller is still in the tree.
// See OnSeal and OnCovered on the host, and InTree.
