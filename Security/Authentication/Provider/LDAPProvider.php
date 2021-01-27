<?php

namespace STG\DEIM\Security\Bundle\LDAPAuthenticationBundle\Security\Authentication\Provider;

use SoapClient;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * LDAPProvider uses a DaoAuthenticationProvide to retrieve the user for a 
 * UsernamePasswordToken.
 *
 * @author Alejandro Azario <aazario@santafe.gov.ar>
 * @author Claudio Zonta <czonta@santafe.gov.ar>
 * @author Fernando Pradolini <fpradolini@santafe.gov.ar>
 */
class LDAPProvider extends DaoAuthenticationProvider
{

    private $userProvider;
    private $endpoint;

    /**
     * {@inheritdoc}
     */
    public function __construct(UserProviderInterface $userProvider, $endpoint, $providerKey)
    {
        parent::__construct($userProvider, new UserChecker(), $providerKey, new EncoderFactory(array()));

        $this->userProvider = $userProvider;
        $this->endpoint = $endpoint;
    }

    /**
     * {@inheritdoc}
     */
    protected function checkAuthentication(UserInterface $user, UsernamePasswordToken $token)
    {
        $currentUser = $token->getUser();

        if ($currentUser instanceof UserInterface) {
            if ($currentUser->getPassword() !== $user->getPassword()) {
                throw new BadCredentialsException('The credentials were changed from another session');
            }
        } else {
            if ("" === ($presentedPassword = $token->getCredentials())) {
                throw new BadCredentialsException('The presented password cannot be empty');
            }

            $soapClient = new SoapClient($this->endpoint);

            $inMessage = array('mail' => $token->getUsername(), 'password' => $presentedPassword);
            $soapResponse = $soapClient->userAuthenticate(array("inMessage" => $inMessage));

            if (empty($soapResponse->cn)) {
                throw new BadCredentialsException('The presented password is invalid');
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function retrieveUser($username, UsernamePasswordToken $token)
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            // username - mail intranet
            $soapClient = new SoapClient($this->endpoint);
            $soapResponse = $soapClient->getUsuario(array('criterio' => $username));

            // uid - iup (identificador único provincial)
            if (empty($soapResponse->uid)) {
                throw new BadCredentialsException('The presented password is invalid');
            }

            $user = $this->userProvider->loadUserByUsername($soapResponse->uid);
            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a UserInterface object');
            }

            return $user;
        } catch (UsernameNotFoundException $notFound) {
            $notFound->setUsername($username);
            throw $notFound;
        } catch (\Exception $repositoryProblem) {
            $ex = new AuthenticationServiceException($repositoryProblem->getMessage(), 0, $repositoryProblem);
            $ex->setToken($token);
            throw $ex;
        }
    }

}
