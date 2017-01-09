<?php

/*
 * This file is part of the EasySecurityBundle.
 *
 * (c) Javier Eguiluz <javier.eguiluz@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace EasyCorp\Bundle\EasySecurityBundle;

use Mmoreram\BaseBundle\SimpleBaseBundle;

/**
 * Class EasySecurityBundle
 */
class EasySecurityBundle extends SimpleBaseBundle
{
    /**
     * get config files.
     *
     * @return array
     */
    public function getConfigFiles() : array
    {
        return [
            'services.yml'
        ];
    }
}
