# Hiding reader library

## Overview

The GhostModeGuard package provides functionality for reading computed hiding risk messages. It employs asymmetric cryptography, specifically AES, for secure message handling.

## Installation

To use GhostModeGuard, first, install the package by importing it into your project:

```go
import (
	"github.com/ghostmodeguard/hiding"
)
```

## Usage

Request a private key as explained [here](https://www.npmjs.com/package/ghost-mode-guard-hiding):

```bash
curl -X 'POST' \
'https://api.ghostmodeguard.com/trust/v1/client?domain=[domain of your frontend application]' \
-H 'accept: application/json'
```

Store it on your application, then create an AESReader instance

```go
aesKey := "your_aes_key_fetched_from_ghost_mode_guard"
reader, err := hiding.NewAESReader(aesKey)
if err != nil {
// Handle error
}
```

The NewAESReader function takes a series of 32 characters as a string and returns an instance of the Reader interface, which allows you to read computed hiding risk messages.

Read a Computed Hiding Risk Message

```go
encryptedMessage := "encrypted_message_here"
computedHidingRisk, err := reader.Read(encryptedMessage)
if err != nil {
// Handle error
}

// Access computed hiding risk data
// computedHidingRisk contains the decrypted and parsed message
```

The Read method decrypts the given message using the private key and returns a ComputedHidingRisk structure, containing the parsed message.

## Example

```go
package main

import (
	"fmt"
	"github.com/ghostmodeguard/hiding"
)

func main() {
    privateKey := "your_aes_key_fetched_from_ghost_mode_guard"
    reader, err := hiding.NewAESReader(privateKey)
    if err != nil {
        // Handle error
    }

    encryptedMessage := "encrypted_message_here"
    computedHidingRisk, err := reader.Read(encryptedMessage)
    if err != nil {
        // Handle error
    }

    // Access computed hiding risk data
    fmt.Printf("Computed Hiding Risk: %+v\n", computedHidingRisk)
}
```

## Important Notes

- Ensure that you handle errors appropriately, especially during the creation of the AESReader instance and when reading the computed hiding risk message.
- The private key should be kept confidential and not shared publicly.

## License

GhostModeGuard hiding library reader is licensed under the MIT License. Feel free to use, modify, and distribute it according to the terms of the license.
