<%
if (session.getAttribute("username") == null)
	response.sendRedirect("login.jsp");
%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<!-- <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.6.3/css/all.css"> -->
<link rel="stylesheet" href="css/login.css" />
<style>
</style>
</head>
<body>
<%
String action = (String) session.getAttribute("action");

//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
//System.out.println(formatter.format(date));
String strDate = formatter.format(date);
String messageForgot = (String)session.getAttribute("messageForgot");
%>
	<!-- <h1>Login & registration Form</h1> -->
	<div class="content">
		<div class="container">
			<div class="menu">
				<!-- <img src="images/logowallet.png" alt="Italian Trulli" height="40px">&nbsp;&nbsp;&nbsp;
				<img src="images/nccblogo.png" alt="Italian Trulli" height="40px"> -->
				<img src="images/matadorgrouplogo.png" alt="Italian Trulli" height="70px">
				<br> <br>
				<div>
					<span class="login-text">Sales Management System</span><br> <span
						class="login-text-alt">Please provide  Mobile number to reset your password
						</span>
						<br>
						${messageForgot}
				</div>
			</div>
			<div class="login-square-container">
				<div class="login-square">
					<form action="PasswordController" method="post" name="frmSave">
						<div class="input-container">
							<i class="fa fa-user icon"></i> <input class="input-field"
								type="text" placeholder="Mobile Number" name="mobile" id="mobile" maxlength=30 size=40 required>
						</div>
						
						<button class="btnblck" style="vertical-align: middle">
							<span>submit</span>
						</button>
					</form>
					<br> <br>
					<div class="forgot-password">
						<%-- <a href="${pageContext.request.contextPath}/login.jsp" target="_blank"><span>Return</span></a> --%>
						<a href="${pageContext.request.contextPath}/login.jsp"><span>Return</span></a>
					</div>
				</div>
			</div>
			<hr>
			<div class="copyright-link">
				<h5>Business Solution. Copyright © 2019 Rashed. All Rights Reserved.</h5>
			</div>
		</div>
	</div>

</body>