<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\EmailVerifier;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use SymfonyCasts\Bundle\VerifyEmail\Exception\VerifyEmailExceptionInterface;

class RegistrationController extends AbstractController
{
    private EmailVerifier $emailVerifier;

    public function __construct(EmailVerifier $emailVerifier)
    {
        $this->emailVerifier = $emailVerifier;
    }

    #[Route('/register', name: 'app_registration', methods: 'POST')]
    public function index(Request $request, UserPasswordHasherInterface $userPasswordHasher, EntityManagerInterface $entityManager, ValidatorInterface $validator): Response
    {
        $parameters = json_decode($request->getContent(), true);

        $user = new User();
        $user->setEmail($parameters['email']);
        $user->setPlainPassword($parameters['password']);
        if ($parameters['password'] === $parameters['confirmPassword']) {
            $user->setPassword($userPasswordHasher->hashPassword($user, $user->getPlainPassword()));
        }
        $errors = $validator->validate($user);
        if (count($errors)>0){
            $errorsString = (string) $errors;
            return new Response($errorsString);
        }
        $user->eraseCredentials();
        $entityManager->persist($user);
        $entityManager->flush();
        // generate a signed url and email it to the user
        $this->emailVerifier->sendEmailConfirmation(
            'app_verify_email',
            $user,
            (new TemplatedEmail())
                ->from(new Address('mailer@example.com', 'AcmeMailBot'))
                ->to($user->getEmail())
                ->subject('Please Confirm your Email')
                ->htmlTemplate('registration/confirmation_email.html.twig')
        );
        // do anything else you need here, like send an email


        return new Response($user->getEmail(), 200);
    }

    #[Route('/verify/email', name: 'app_verify_email')]
    public function verifyUserEmail(Request $request, UserRepository $userRepository): Response
    {
        $id = $request->query->get('id'); // retrieve the user id from the url

        // Verify the user id exists and is not null
        if (null === $id) {
            return $this->json(['error'=>'User not found.']);
        }

        $user = $userRepository->find($id);

        // Ensure the user exists in persistence
        if (null === $user) {
            return $this->json(['error'=>'User not found.']);
        }
        if ($user->isIsVerified()){
            return $this->json(['error'=>'Email already verified.']);
        }

        // validate email confirmation link, sets User::isVerified=true and persists
        try {
            $this->emailVerifier->handleEmailConfirmation($request, $user);
        } catch (VerifyEmailExceptionInterface $exception) {

            return $this->json(['verify_email_error'=>$exception->getReason()]);
        }


        return $this->json(['success'=>'Your email address has been verified.']);
    }
}
