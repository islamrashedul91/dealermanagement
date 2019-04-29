package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.rashed.pharmacy.dao.EmailUtility;
import com.rashed.pharmacy.util.GetHeader;

@WebServlet("/EmailSendingController")
public class EmailSendingController extends HttpServlet {
	private String host;
	private String port;
	private String user;
	private String pass;

	public void init() {
		// reads SMTP server setting from web.xml file
		ServletContext context = getServletContext();
		 
		/*host = "smtp.gmail.com";
		port = "587";
		user = "islamrashedul91@gmail.com";
		pass = "kmri280386";*/
		
		/* or param-value get from web.xml [S]
		host = getServletContext().getInitParameter("host");
		port = getServletContext().getInitParameter("port");
		user = getServletContext().getInitParameter("user");
		pass = getServletContext().getInitParameter("pass");
		or param-value get from web.xml [E]*/
		// or param-value get from web.xml [S]
		/*host = context.getInitParameter("host");
		port = context.getInitParameter("port");
		user = context.getInitParameter("user");
		pass = context.getInitParameter("pass");*/
		// or param-value get from web.xml [E]
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response, String email, String verificationCode, String strSubject) throws ServletException, IOException {
		// reads SMTP server setting from web.xml file [S]
		/*host = "smtp.gmail.com";
		port = "587";
		user = "islamrashedul91@gmail.com";
		pass = "kmri280386";*/
		GetHeader getHeader = new GetHeader();
		host = getHeader.getHost();
		port = getHeader.getPort();
		user = getHeader.getUser();
		pass = getHeader.getPass();
		// reads SMTP server setting from web.xml file [E]
		
		// reads form fields		
		String recipient = email;
		String subject = strSubject;
		String content = verificationCode;

		String resultMessage = "";

		try {
			EmailUtility.sendEmail(host, port, user, pass, recipient, subject,
					content);
			resultMessage = "The e-mail was sent successfully";
		} catch (Exception ex) {
			ex.printStackTrace();
			resultMessage = "There were an error: " + ex.getMessage();
		} /*finally {
			request.setAttribute("Message", resultMessage);
			getServletContext().getRequestDispatcher("/login.jsp").forward(
					request, response);
		}*/
	}
}
