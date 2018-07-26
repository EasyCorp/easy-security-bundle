-----

# THIS BUNDLE IS NO LONGER MAINTAINED. SYMFONY 3.4 ADDED A [SIMILAR FEATURE](https://github.com/symfony/symfony/pull/24337) SO THIS IS NO LONGER NEEDED.

-----

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

Once installed, this bundle creates a new service called `security` that
provides lots of shortcuts for the most common security operations. The
main advantages over the Symfony Security component/bundle are:

**1) It hides internal complexity**

The Security component and bundle are some of the most complex Symfony pieces.
They require you to learn lots of internal details that you probably don't
care about:

```php
// get the current user
$user = $this->get('security.token_storage')->getToken()->getUser();
// check their permissions
$user = $this->get('security.authorization_checker')->isGranted('ROLE_ADMIN');
// get the last login attempt error, if any
$error = $this->get('security.authentication_utils')->getLastAuthenticationError();
```

This bundle hides this complexity centralizing all the operations under the
`security` service:

```php
// get the current user
$user = $this->get('security')->getUser();
// check their permissions
$user = $this->get('security')->isGranted('ROLE_ADMIN');
// get the last login attempt error, if any
$error = $this->get('security')->getLoginError();
```

**2) It makes code less verbose**

Sometimes, the code needed to do common tasks is ridiculously verbose. For
example, to login a user programmatically, Symfony requires you to do the following:

```php
$user = ...
$token = new UsernamePasswordToken($user, $user->getPassword(), 'main', $user->getRoles());
$token->setAuthenticated(true);
$this->get('security.token_storage')->setToken($token);
$this->get('session')->set('_security_main', serialize($token));
$this->get('session')->save();
```

This bundle makes login a user as simple as it can be:

```php
$user = ...
$this->get('security')->login($user);
```

**3) It fixes some unintuitive behaviors**

In Symfony applications, the way to check if a user is anonymous, remembered or
fully authenticated doesn't work as most people expect. For example, if a user
logs in with their username + password using a form login, this will happen:

```php
// returns true
$this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_ANONYMOUSLY');
// returns true
$this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_REMEMBERED');
// returns true
$this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_FULLY');
```

Symfony grants the anonymous and remembered attributes to fully authenticated
users, so it's complicated to differentiate between them. This bundle changes
this unintuitive behavior and helps you know if a user is truly anonymous,
remembered or authenticated. In the same example as before:

```php
// returns false
$this->get('security')->isAnonymous();
// returns false
$this->get('security')->isRemembered();
// returns true
$this->get('security')->isFullyAuthenticated();
```

### Injecting the `security` service

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
