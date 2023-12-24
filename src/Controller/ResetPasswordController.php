<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use SymfonyCasts\Bundle\ResetPassword\Controller\ResetPasswordControllerTrait;
use SymfonyCasts\Bundle\ResetPassword\Exception\ResetPasswordExceptionInterface;
use SymfonyCasts\Bundle\ResetPassword\ResetPasswordHelperInterface;

class ResetPasswordController extends AbstractController
{

    use ResetPasswordControllerTrait;

    public function __construct(
        private readonly ResetPasswordHelperInterface $resetPasswordHelper,
        private readonly EntityManagerInterface $entityManager,
        private MailerInterface $mailer,
    ) {
    }

    #[Route('/reset-password', name: 'app_forgot_password_request', methods: 'POST')]
    public function index(Request $request): Response
    {
        $parameters = json_decode($request->getContent(), true);
        return $this->sendPasswordResetEmail($parameters['email']);
    }

    private function sendPasswordResetEmail(string $email): Response
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy([
            'email' => $email
        ]);
        if (!$user) {
            return $this->json(['error' => 'User not found.']);
            // return $this->redirectToRoute('app_check_email');
        }
        try {
            $resetToken = $this->resetPasswordHelper->generateResetToken($user);
        } catch (ResetPasswordExceptionInterface $e) {
            return $this->json(['error' => $e->getReason()]);
            // return $this->redirectToRoute('app_check_email');
        }
        $email = (new TemplatedEmail())
            ->from(new Address('mailer@example.com', 'AcmeMailBot'))
            ->to($user->getEmail())
            ->subject('Reset Password')
            ->htmlTemplate('_email/reset_password_confirm.html.twig')
            ->context([
                'resetToken' => $resetToken,
            ]);
        $this->mailer->send($email);
        $this->setTokenObjectInSession($resetToken);
        return $this->json(['email' => 'Email sent']);
        // return $this->redirectToRoute('app_check_email');
    }

    #[Route('/reset-password/check-email/{token}', name: 'app_check_email', methods: 'GET')]
    public function checkEmail(string $token = null): Response
    {
        // Generate a fake token if the user does not exist or someone hit this page directly.
        // This prevents exposing whether or not a user was found with the given email address or not
        if (null === ($resetToken = $this->getTokenObjectFromSession())) {
            $resetToken = $this->resetPasswordHelper->generateFakeResetToken();
        }

        return $this->json(['resetToken' => $resetToken->getToken()]);
    }
    
    #[Route(path: '/reset-password/{token}', name: 'app_reset_password', methods: ['POST', 'GET'])]
    public function reset(Request $request, UserPasswordHasherInterface  $userPasswordHasher, string $token = null): Response
    {
        $session = $request->getSession();

        if ($token) {
            $this->storeTokenInSession($token);
            $json = json_decode($request->getContent(), true);
            $session->set('password', $json['password']);
            return $this->redirectToRoute('app_reset_password');
        }
        $token = $this->getTokenFromSession();

        if (null === $token) {
            throw $this->createNotFoundException('No reset password token found in the URL or in the session.');
        }
        try {
            $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
        } catch (ResetPasswordExceptionInterface $e) {
            throw $e;
            // return $this->json(['errors' => $e->getReason()]);
        }
        // A password reset token should be used only once, remove it.
        $this->resetPasswordHelper->removeResetRequest($token);
        $plainPassword = $session->get('password');

        // Encode(hash) the plain password, and set it.
        $encodedPassword = $userPasswordHasher->hashPassword(
            $user,
            $plainPassword
        );

        $user->setPassword($encodedPassword);
        $this->entityManager->flush();

        // The session is cleaned up after the password has been changed.
        $this->cleanSessionAfterReset();

        return $this->json('Password was changed with success');
    }
}
