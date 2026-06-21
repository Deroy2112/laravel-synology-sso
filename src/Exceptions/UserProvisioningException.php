<?php

namespace Deroy2112\LaravelSynologySso\Exceptions;

use RuntimeException;

/**
 * Thrown when a local user cannot be provisioned for an authenticated Synology
 * SSO user — for example a missing email, a misconfigured user model, or an
 * unknown user while just-in-time creation is disabled.
 */
class UserProvisioningException extends RuntimeException
{
    //
}
