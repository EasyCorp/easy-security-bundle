<?php
/**
 * File header placeholder
 */

namespace EasyCorp\Bundle\EasySecurityBundle\Security;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class SecurityFastAccessor
 */
trait SecurityFastAccessor
{
    /**
     * Returns the current application user.
     *
     * @return UserInterface|null
     */
    public function getUser() : ? UserInterface
    {
        return $this
            ->getSecurity()
            ->getUser();
    }

    /**
     * When impersonating a user, it returns the original user who started
     * the impersonation.
     *
     * @return mixed
     */
    public function getImpersonatingUser()
    {
        return $this
            ->getSecurity()
            ->getImpersonatingUser();
    }

    /**
     * Checks if the attributes (usually security roles) are granted for the
     * current application user and the optional given object.
     *
     * @param mixed $attributes
     * @param mixed $object
     *
     * @return bool
     */
    public function isGranted($attributes, $object = null) : bool
    {
        return $this
            ->getSecurity()
            ->isGranted(
                $attributes,
                $object
            );
    }

    /**
     * Returns the error of the last failed login attempt, if any.
     *
     * @return AuthenticationException|null
     */
    public function getLoginError() : ? AuthenticationException
    {
        return $this
            ->getSecurity()
            ->getLoginError();
    }

    /**
     * Returns the username of the last failed login attempt, if any.
     *
     * @return string|null
     */
    public function getLoginUsername() : ? string
    {
        return $this
            ->getSecurity()
            ->getLoginUsername();
    }

    /**
     * Returns true if the current application user (or the optionally given user)
     * has the given role. It takes into account the full role hierarchy.
     *
     * @param mixed         $role
     * @param UserInterface $user
     *
     * @return bool
     */
    public function hasRole($role, UserInterface $user = null) : bool
    {
        return $this
            ->getSecurity()
            ->hasRole(
                $role,
                $user
            );
    }

    /**
     * Returns true if the current application user (or the optionally given user)
     * is anonymous. This behaves differently than Symfony built-in methods and
     * it returns true only when the user is really anonymous.
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isAnonymous(UserInterface $user = null) : bool
    {
        return $this
            ->getSecurity()
            ->isAnonymous($user);
    }

    /**
     * Returns true if the current application user (or the optionally given user)
     * is remembered. This behaves differently than Symfony built-in methods and
     * it returns true only when the user is really remembered and they haven't
     * introduced their credentials (username and password).
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isRemembered(UserInterface $user = null) : bool
    {
        return $this
            ->getSecurity()
            ->isRemembered($user);
    }

    /**
     * Returns true if the current application user (or the optionally given user)
     * is authenticated because they have introduced their credentials (username
     * and password).
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isFullyAuthenticated(UserInterface $user = null) : bool
    {
        return $this
            ->getSecurity()
            ->isFullyAuthenticated($user);
    }

    /**
     * Returns true if the current application user (or the optionally given user)
     * is authenticated in any way (because they have introduced their credentials
     * (username and password) or they have been remembered).
     *
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isAuthenticated(UserInterface $user = null) : bool
    {
        return $this
            ->getSecurity()
            ->isAuthenticated($user);
    }

    /**
     * It logs in the given user in the 'main' application firewall (or the
     * optionally given firewall name).
     *
     * @param UserInterface $user
     * @param string $firewallName
     *
     * @return UserInterface
     */
    public function login(
        UserInterface $user,
        string $firewallName = 'main'
    ) : UserInterface
    {
        return $this
            ->getSecurity()
            ->login(
                $user,
                $firewallName
            );
    }

    /**
     * Returns the given plain password encoded/hashed using the encoder of the
     * current application user or the optionally given user.
     *
     * @param string $plainPassword
     * @param UserInterface   $user
     *
     * @return string
     */
    public function encodePassword(
        string $plainPassword,
        UserInterface $user = null
    ) : string
    {
        return $this
            ->getSecurity()
            ->encodePassword(
                $plainPassword,
                $user
            );
    }

    /**
     * Returns true if the given plain password is valid for the current
     * application user or the optionally given user.
     *
     * @param string $plainPassword
     * @param UserInterface   $user
     *
     * @return bool
     */
    public function isPasswordValid(
        string $plainPassword,
        UserInterface $user = null
    ) : bool
    {
        return $this
            ->getSecurity()
            ->isPasswordValid(
                $plainPassword,
                $user
            );
    }

    /**
     * Get security service
     *
     * @return Security
     */
    protected function getSecurity()
    {
        return $this
            ->container
            ->get('security');
    }
}