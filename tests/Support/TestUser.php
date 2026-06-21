<?php

namespace Deroy2112\LaravelSynologySso\Tests\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * Minimal Eloquent model standing in for a consumer's User model in
 * provisioning tests.
 *
 * @property int $id
 * @property string|null $name
 * @property string $email
 */
final class TestUser extends Model
{
    protected $table = 'users';

    /** @var list<string> */
    protected $fillable = ['name', 'email'];
}
