<?php

namespace Deroy2112\LaravelSynologySso\Exceptions;

use RuntimeException;

/**
 * Thrown when the PKCE code verifier is absent from the session during the
 * token exchange — typically because the authorization request expired, the
 * session was lost, or the callback was reached without a preceding redirect.
 */
class MissingPkceVerifierException extends RuntimeException
{
    //
}
