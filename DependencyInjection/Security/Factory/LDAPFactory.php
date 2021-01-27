<?php

namespace STG\DEIM\Security\Bundle\LDAPAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\FormLoginFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

/**
 * FormLoginFactory uses a AbstractFactory to creates services for form login
 * authentication.
 * 
 * @author Alejandro Azario <aazario@santafe.gov.ar>
 * @author Claudio Zonta <czonta@santafe.gov.ar>
 * @author Fernando Pradolini <fpradolini@santafe.gov.ar>
 */
class LDAPFactory extends FormLoginFactory
{

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $provider = 'stg.deim.security.authentication.provider.ldap.' . $id;
        $container
                ->setDefinition($provider, new DefinitionDecorator('stg.deim.security.authentication.provider.ldap'))
                ->replaceArgument(0, new Reference($userProviderId))
                ->replaceArgument(2, $id)
        ;

        return $provider;
    }

    protected function getListenerId()
    {
        return 'security.authentication.listener.form';
    }

    public function getKey()
    {
        return 'ldap-form';
    }

}
