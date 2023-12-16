<?php

namespace App\Controller;

use ApiPlatform\Api\IriConverterInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SecurityController extends AbstractController
{
    
    #[Route('/login', name: 'app_login', methods: ['POST'])]
    public function index(IriConverterInterface $iriConverter): Response
    {
        if (!$this->isGranted('IS_AUTHENTICATED_FULLY')){
            return $this->json([
                'error' => 'Invalid login request: check the Content-Type header.'
            ]);
        }
        
        return new Response(null, 204, [
            'location' => $iriConverter->getIriFromResource($this->getUser())
        ]);
    }
}
