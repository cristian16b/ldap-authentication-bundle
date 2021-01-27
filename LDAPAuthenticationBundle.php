<?php

namespace STG\DEIM\Security\Bundle\LDAPAuthenticationBundle;

use STG\DEIM\Security\Bundle\LDAPAuthenticationBundle\DependencyInjection\Security\Factory\LDAPFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class LDAPAuthenticationBundle extends Bundle
{

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new LDAPFactory());
    }

}
