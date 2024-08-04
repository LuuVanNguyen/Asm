package com.poly.service;

import com.poly.entity.Mailer;
import jakarta.mail.MessagingException;

import java.io.UnsupportedEncodingException;

public interface MailerService {

    void send(Mailer mail) throws MessagingException;

    void send(String to, String subject, String body) throws MessagingException;

    void sendEmail(String recipientEmail, String link) throws MessagingException, UnsupportedEncodingException;

}
