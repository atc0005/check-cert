// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import "errors"

var (
	// ErrVersionRequested indicates that the user requested application
	// version information.
	ErrVersionRequested = errors.New("version information requested")

	// ErrInvalidPosArgPattern indicates that the user provided an invalid
	// pattern for a positional argument.
	ErrInvalidPosArgPattern = errors.New("invalid positional argument pattern")

	// ErrUnsupportedOption indicates that an unsupported option was specified.
	ErrUnsupportedOption = errors.New("unsupported option")

	// ErrInvalidCertificateMetadataPayloadFormatVersion indicates that an
	// invalid certificate metadata payload format version was specified.
	ErrInvalidCertificateMetadataPayloadFormatVersion = errors.New("invalid certificate metadata payload format version")

	// ErrIncompatibleCertificateMetadataPayloadFormatVersion indicates that
	// an certificate metadata payload format version was specified that is
	// incompatible with other chosen flags/values.
	ErrIncompatibleCertificateMetadataPayloadFormatVersion = errors.New("incompatible certificate metadata payload format version")
)
