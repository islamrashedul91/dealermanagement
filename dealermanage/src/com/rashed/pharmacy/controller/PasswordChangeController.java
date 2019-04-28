package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.rashed.pharmacy.model.OwnerInfo;
import com.rashed.pharmacy.dao.OwnerInfoDAO;


public class PasswordChangeController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private OwnerInfoDAO dao;
	
	public PasswordChangeController() {
        super();
        dao = new OwnerInfoDAO();
    }
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		
		String mobile = request.getParameter("mobile");
		String curpassword = request.getParameter("password");
		String newpassword = request.getParameter("newpassword");
		String conpassword = request.getParameter("conpassword");
		// for forget password [S]
		String verificationCode = request.getParameter("verificationCode");
		String otp = request.getParameter("otp");
		// for forget password [E]
		// MD5 password encrypt [S]
		StringBuilder sb = null;
		String md5Password = "";
		String message = "";
		if(curpassword != null) {
			try{
	
		        MessageDigest md = MessageDigest.getInstance("MD5");
		        byte[] hashInBytes = md.digest(curpassword.getBytes(StandardCharsets.UTF_8));
		
		        sb = new StringBuilder();
		        //sb = new StringBuilder();
		        for (byte b : hashInBytes) {
		            sb.append(String.format("%02x", b));
		        }
		        //System.out.println(sb.toString());
		        md5Password = sb.toString();
			} catch (Exception e){
	    		e.printStackTrace();
	    	}
		
        // MD5 password encrypt [E]
		
		// MD5 password encrypt [S]
		try {
		if(dao.validate(mobile, md5Password)) {
		// MD5 password encrypt [E]
			
			if (newpassword.equals(conpassword)){
				// MD5 password encrypt [S]
				sb = null;
				String newmd5Password = "";
				try{

			        MessageDigest md = MessageDigest.getInstance("MD5");
			        byte[] hashInBytes = md.digest(newpassword.getBytes(StandardCharsets.UTF_8));
			
			        sb = new StringBuilder();
			        //sb = new StringBuilder();
			        for (byte b : hashInBytes) {
			            sb.append(String.format("%02x", b));
			        }
			        //System.out.println(sb.toString());
			        newmd5Password = sb.toString();
				} catch (Exception e){
		    		e.printStackTrace();
		    	}
		        // MD5 password encrypt [E]
				OwnerInfo oi = new OwnerInfo();
				
				oi.setMobile(request.getParameter("mobile"));
				oi.setPassword(newmd5Password);
				oi.setUpdated(request.getParameter("updated"));
				
				message = "Successfully password changed !!!";
				oi.setMobile(mobile);
				dao.changePassword(oi);

				RequestDispatcher rd = request.getRequestDispatcher("base.jsp");
				
				request.setAttribute("message", message);
				
				rd.forward(request, response);
			} else {
				message = "** Please input same password for New Password and Confirm Password **";
				HttpSession session = request.getSession();
				session.setAttribute("message", message);
				RequestDispatcher rd = request.getRequestDispatcher("passwordChange.jsp");
				rd.include(request, response);
			}
			
		} else {
			//out.println("<h3 align='center'>Invalid userid or password!!</h3>");
			message = "** Invalid userid or password **";
			HttpSession session = request.getSession();
			session.setAttribute("message", message);
			RequestDispatcher rd = request.getRequestDispatcher("passwordChange.jsp");
			rd.include(request, response);
			//response.sendRedirect("Login.jsp");
		}
		} catch(Exception e) {
			e.printStackTrace();
		}
	} // for forget password [S]
		else if (otp.equals(verificationCode)){ 
			if (newpassword.equals(conpassword)){
				// MD5 password encrypt [S]
				sb = null;
				String newmd5Password = "";
				try{

			        MessageDigest md = MessageDigest.getInstance("MD5");
			        byte[] hashInBytes = md.digest(newpassword.getBytes(StandardCharsets.UTF_8));
			
			        sb = new StringBuilder();
			        //sb = new StringBuilder();
			        for (byte b : hashInBytes) {
			            sb.append(String.format("%02x", b));
			        }
			        //System.out.println(sb.toString());
			        newmd5Password = sb.toString();
				} catch (Exception e){
		    		e.printStackTrace();
		    	}
		        // MD5 password encrypt [E]
				OwnerInfo oi = new OwnerInfo();
				
				oi.setMobile(request.getParameter("mobile"));
				oi.setPassword(newmd5Password);
				oi.setUpdated(request.getParameter("updated"));
				
				message = "Successfully password changed !!!";
				oi.setMobile(mobile);
				dao.changePassword(oi);

				RequestDispatcher rd = request.getRequestDispatcher("login.jsp");
				
				request.setAttribute("message", message);
				
				rd.forward(request, response);
			} else {
				message = "** Please input same password for New Password and Confirm Password **";
				HttpSession session = request.getSession();
				session.setAttribute("message", message);
				RequestDispatcher rd = request.getRequestDispatcher("passwordChange.jsp");
				rd.include(request, response);
			}
		} else {
			//out.println("<h3 align='center'>Invalid userid or password!!</h3>");
			message = "** Invalid verification code **";
			HttpSession session = request.getSession();
			session.setAttribute("message", message);
			RequestDispatcher rd = request.getRequestDispatcher("forgetPasswordOTP.jsp");
			rd.include(request, response);
			//response.sendRedirect("Login.jsp");
		}
		// for forget password [E]
	}
}

