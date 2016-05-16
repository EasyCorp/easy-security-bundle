EasySecurityBundle
==================

This bundle provides useful shortcuts to hide the Symfony Security component
complexity.

Installation
------------

### Step 1: Download the Bundle

```bash
$ composer require easycorp/easy-security-bundle
```

This command requires you to have Composer installed globally, as explained
in the [Composer documentation](https://getcomposer.org/doc/00-intro.md).

### Step 2: Enable the Bundle

```php
<?php
// app/AppKernel.php

// ...
class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = array(
            // ...
            new EasyCorp\Bundle\EasySecurityBundle\EasySecurityBundle(),
        );
    }

    // ...
}
```

Basic Usage
-----------

Once installed, this bundle creates a new service called `security` in your
Symfony application. This service provides lots of shortcuts for the most common
security operations. For example, to get the current application user in a
controller:

```php
// in a Symfony standard application
$user = $this->get('security.token_storage')->getToken()->getUser();

// with this bundle
$user = $this->get('security')->getUser();
```

These shortcuts can be used across your application if you inject the `security`
service. For example, if you define your services in YAML format:

```yaml
# app/config/services.yml
services:
    app.my_service:
        # ...
        arguments: ['@security']
```

Then, update the constructor of your service to get the `security` service:

```php
// src/AppBundle/MyService.php
// ...
use EasyCorp\Bundle\EasySecurityBundle\Security\Security;

class MyService
{
    private $security;

    public function __construct(Security $security)
    {
        $this->security = $security;
    }

    public function myMethod()
    {
        // ...
        $user = $this->security->getUser();
    }
}
```

List of Shortcuts
-----------------

### Getting users

* `getUser()`: returns the current application user.
* `getImpersonatingUser()`: when impersonating a user, it returns the original
  user who started the impersonation.

### Checking permissions

* `isGranted($attributes, $object = null)`: checks if the attributes (usually
  security roles) are granted for the current application user and the
  optionally given object.
* `hasRole($role, $user = null)`: returns `true` if the current application user
  (or the optionally given user) has the given role. It takes into account the
  full role hierarchy.

### Types of users

* `isAnonymous($user = null)`: returns `true` if the current application user (or
  the optionally given user) is anonymous. This behaves differently than Symfony
  built-in methods and it returns `true` only when the user is really anonymous.
* `isRemembered($user = null)`: returns `true` if the current application user
  (or the optionally given user) is remembered. This behaves differently than
  Symfony built-in methods and it returns true only when the user is really
  remembered and they haven't introduced their credentials (username and password).
* `isFullyAuthenticated($user = null)`: returns `true` if the current application
  user (or the optionally given user) is authenticated because they have
  introduced their credentials (username and password).
* `isAuthenticated($user = null)`: returns `true` if the current application user
  (or the optionally given user) is authenticated in any way (because they have
  introduced their credentials (username and password) or they have been remembered).

### Login

* `login(UserInterface $user, $firewallName = 'main')`: it logs in the given user
  in the `main` application firewall (or the optionally given firewall name).
* `getLoginError()`: returns the error of the last failed login attempt, if any.
* `getLoginUsername()`: returns the username of the last failed login attempt,
  if any.

### Passwords

* `encodePassword($plainPassword, $user = null)`: returns the given plain
  password encoded/hashed using the encoder of the current application user or
  the optionally given user.
* `isPasswordValid($plainPassword, $user = null)`: returns `true` if the given
  plain password is valid for the current application user or the optionally
  given user.
