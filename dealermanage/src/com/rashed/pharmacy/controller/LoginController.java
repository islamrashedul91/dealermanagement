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

import com.rashed.pharmacy.dao.OwnerInfoDAO;


public class LoginController extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	OwnerInfoDAO oidao;
	
	public LoginController() {
        super();
        oidao = new OwnerInfoDAO();
    }
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		HttpSession session = request.getSession();
		session.removeAttribute("username");
		session.invalidate();
		response.sendRedirect("login.jsp");
	}

	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		
		/*String userid = request.getParameter("userid");
		String password = request.getParameter("password");*/
		String userid = request.getParameter("mobile");
		String password = request.getParameter("password");
		// MD5 password encrypt [S]
		StringBuilder sb = null;
		String md5Password = "";
		try{

	        MessageDigest md = MessageDigest.getInstance("MD5");
	        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
	
	        sb = new StringBuilder();
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
		if(oidao.validate(userid, md5Password)) {
		// MD5 password encrypt [E]
			//logic for Logout and (without login cannot open Index.jsp)
			HttpSession session = request.getSession();
			session.setAttribute("username", userid);
			//get ip address and host name [S]
			InetAddress inetAddress = InetAddress.getLocalHost();
			String ipAddress = inetAddress.getHostAddress();
			String hostName = inetAddress.getHostName();
	        
			session.setAttribute("ipAddress", ipAddress);
			session.setAttribute("hostName", hostName);
			//get ip address and host name [E]
			
			
			// display name for specific owner [S]
			session.setAttribute("ownerInfos", oidao.getOwnerInfoByMobile(userid));
			//String ownerId = oidao.getOwnerInfoByMobile(userid).getOwner_id();
			session.setAttribute("ownerId", oidao.getOwnerInfoByMobile(userid).getOwner_id());
			session.setAttribute("ownerName", oidao.getOwnerInfoByMobile(userid).getOwner_name());
			// display name for specific owner [E]
			
			RequestDispatcher rd = request.getRequestDispatcher("base.jsp");
			rd.include(request, response);
		} else {
			//out.println("<h3 align='center'>Invalid userid or password!!</h3>");
			String logginErrorMessage = "** Invalid userid or password **";
			HttpSession session = request.getSession();
			session.setAttribute("logginErrorMessage", logginErrorMessage);
			RequestDispatcher rd = request.getRequestDispatcher("login.jsp");
			rd.include(request, response);
			//response.sendRedirect("Login.jsp");
		}
		} catch(Exception e){
			e.printStackTrace();
		}
	}

}
