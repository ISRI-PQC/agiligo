// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package init

import (
	_ "crypto/dsa"
	_ "crypto/ecdh"
	_ "crypto/ecdsa"
	_ "crypto/ed25519"
	_ "crypto/mldsa"
	_ "crypto/rsa"
)
