<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SecurityController extends AbstractController
{
    
    #[Route('/login', name: 'app_login', methods: ['POST'])]
    public function index(): Response
    {
        if (!$this->isGranted('IS_AUTHENTICATED_FULLY')){
            return $this->json([
                'error' => 'Invalid login request: check the Content-Type header.'
            ]);
        }
        /** @var User */
        $user = $this->getUser();
        return $this->json([
            'user' => $user ? $user->getId() : null
        ]);
    }
}
