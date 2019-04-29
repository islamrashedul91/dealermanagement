package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.OwnerInfo;
import com.rashed.pharmacy.dao.OwnerInfoDAO;
import com.rashed.pharmacy.model.Sms;
import com.rashed.pharmacy.dao.SmsDAO;
import com.rashed.pharmacy.controller.EmailSendingController;

public class PasswordController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String FORGET_PASSWORD = "forgetPassword.jsp";
	private static String LOGIN = "login.jsp";
	
	private OwnerInfoDAO oidao;
	private SmsDAO sdao;
	
	String action = "";
	String message = "";
	String randomNumber = "";
	String mobile = "";
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
       
    public PasswordController() {
        super();
        oidao = new OwnerInfoDAO();
        sdao = new SmsDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("forgetPassword")){
			forward = FORGET_PASSWORD;
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		
		String mobile = request.getParameter("mobile");
		
		String messageForgot = "";
		
		if(oidao.validateForgetPassword(mobile)) {
			// random number [S]
			Random rnd = new Random();
		    int number = rnd.nextInt(999999);
		    // this will convert any number sequence into 6 character.
		    //String rnum = String.format("%06d", number);
		    randomNumber = String.format("%06d", number);
		    HttpSession session = request.getSession();
			session.setAttribute("randomNumber", randomNumber);
			session.setAttribute("mobile", mobile);
			// random number [E]
				
			messageForgot = "Verification code send to your email address !!!";
			
			String email = oidao.getOwnerInfoByMobile(mobile).getEmail();
			String verificationCode = "Verification code for forget password is : " + randomNumber;
			String subject = "Forgot Password";
			
			// insert into sms table [S]
			Sms s = new Sms();

			s.setDelivery_status("P");
			s.setMobile(mobile);
			s.setEmail(email);
			s.setSms_body("Verification code for forget password is : " + randomNumber);
			s.setDescription("");
			s.setCreated(strDate);
			s.setUpdated("");
			
			sdao.save(s);
			// insert into sms table [E]
			
			// Verification code send to your email address [S]
			EmailSendingController cont1 = new EmailSendingController();
			
			cont1.doPost(request, response, email, verificationCode, subject);
			// Verification code send to your email address [E]
			
			RequestDispatcher rd = request.getRequestDispatcher("forgetPasswordOTP.jsp");
			request.setAttribute("messageForgot", messageForgot);
			rd.forward(request, response);
			
		} else {
			messageForgot = "** Invalid Mobile number **";
			HttpSession session = request.getSession();
			session.setAttribute("messageForgot", messageForgot);
			RequestDispatcher rd = request.getRequestDispatcher("forgetPassword.jsp");
			rd.include(request, response);
		}
	}

}
