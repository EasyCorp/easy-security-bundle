<?php

/*
 * This file is part of the EasySecurityBundle.
 *
 * (c) Javier Eguiluz <javier.eguiluz@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace EasyCorp\Bundle\EasySecurityBundle\Security;

use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoder;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleHierarchy;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * Provides useful shortcuts to hide the Symfony Security component complexity.
 */
class Security
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * @var UserPasswordEncoder
     */
    private $passwordEncoder;

    /**
     * @var AuthenticationUtils
     */
    private $authenticationUtils;

    /**
     * @var Session
     */
    private $session;

    /**
     * @var RoleHierarchy
     */
    private $roleHierarchy;

    /**
     * Security constructor.
     *
     * @param TokenStorageInterface         $tokenStorage
     * @param AuthorizationCheckerInterface $authorizationChecker
     * @param UserPasswordEncoder           $passwordEncoder
     * @param AuthenticationUtils           $authenticationUtils
     * @param Session                       $session
     * @param RoleHierarchy                 $roleHierarchy
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthorizationCheckerInterface $authorizationChecker,
        UserPasswordEncoder $passwordEncoder,
        AuthenticationUtils $authenticationUtils,
        Session $session,
        RoleHierarchy $roleHierarchy
    )
    {
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
        $this->passwordEncoder = $passwordEncoder;
        $this->authenticationUtils = $authenticationUtils;
        $this->session = $session;
        $this->roleHierarchy = $roleHierarchy;
    }

    /**
     * Returns the current application user.
     *
     * @return UserInterface|null
     */
    public function getUser() : ? UserInterface
    {
        $token = $this
            ->tokenStorage
            ->getToken();

        return $token instanceof TokenInterface
            ? $token->getUser()
            : null;
    }

    /**
     * When impersonating a user, it returns the original user who started
     * the impersonation.
     *
     * @return mixed
     */
    public function getImpersonatingUser()
    {
        if ($this->isGranted('ROLE_PREVIOUS_ADMIN')) {
            foreach ($this->tokenStorage->getToken()->getRoles() as $role) {
                if ($role instanceof SwitchUserRole) {
                    return $role->getSource()->getUser();
                }
            }
        }
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
            ->authorizationChecker
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
            ->authenticationUtils
            ->getLastAuthenticationError();
    }

    /**
     * Returns the username of the last failed login attempt, if any.
     *
     * @return string|null
     */
    public function getLoginUsername() : ? string
    {
        return $this
            ->authenticationUtils
            ->getLastUsername();
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
        $roleName = $role instanceof Role ? $role->getRole() : $role;

        $user = $this->getUserToWorkWith($user);

        if (!($user instanceof UserInterface)) {
            return false;
        }

        if (null === $this->roleHierarchy) {
            return in_array($roleName, $user->getRoles(), true);
        }

        $userRoles = $this->roleHierarchy->getReachableRoles($this->getUserRolesAsObjects($user));
        foreach ($userRoles as $userRole) {
            if ($roleName === $userRole->getRole()) {
                return true;
            }
        }

        return false;
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
        return !$this->isAuthenticated($user);
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
        $user = $this->getUserToWorkWith($user);

        if ($this->isFullyAuthenticated($user)) {
            return false;
        }

        return  $this->isGranted('IS_AUTHENTICATED_REMEMBERED', $user);
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
        $user = $this->getUserToWorkWith($user);

        return $this->isGranted('IS_AUTHENTICATED_FULLY', $user);
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
        $user = $this->getUserToWorkWith($user);

        return
            $this->isGranted('IS_AUTHENTICATED_FULLY', $user) ||
            $this->isGranted('IS_AUTHENTICATED_REMEMBERED', $user);
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
        $token = new UsernamePasswordToken($user, $user->getPassword(), $firewallName, $user->getRoles());
        $token->setAuthenticated(true);
        $this->tokenStorage->setToken($token);

        $this->session->set('_security_'.$firewallName, serialize($token));
        $this->session->save();

        return $user;
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
        $user = $this->getUserToWorkWith($user);

        return $this
            ->passwordEncoder
            ->encodePassword(
                $user,
                $plainPassword
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
        $user = $this->getUserToWorkWith($user);

        return $this
            ->passwordEncoder
            ->isPasswordValid(
                $user,
                $plainPassword
            );
    }

    /**
     * Returns an array with the roles of the given user turned into Role objects,
     * which are needed by methods such as getReachableRoles().
     *
     * @param UserInterface $user
     *
     * @return RoleInterface[]
     */
    private function getUserRolesAsObjects(UserInterface $user) : array
    {
        $userRoles = array();
        foreach ($user->getRoles() as $userRole) {
            $userRoles[] = $userRole instanceof Role ? $userRole : new Role($userRole);
        }

        return $userRoles;
    }

    /**
     * Get the user to work with
     *
     * @param UserInterface|null $user
     *
     * @return null|UserInterface
     */
    private function getUserToWorkWith(?UserInterface $user) : ?UserInterface
    {
        return $user instanceof UserInterface
            ? $user
            : $this->getUser();
    }
}
