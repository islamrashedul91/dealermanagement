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
String mobile = (String)session.getAttribute("mobile");
String verificationCode = (String)session.getAttribute("randomNumber");
String message = (String)session.getAttribute("message");
String messageForgot = (String)session.getAttribute("messageForgot");
%>
	<!-- <h1>Login & registration Form</h1> -->
	<div class="content">
		<div class="container-alt">
			<div class="menu">
				<!-- <img src="images/logowallet.png" alt="Italian Trulli" height="40px">&nbsp;&nbsp;&nbsp;
				<img src="images/nccblogo.png" alt="Italian Trulli" height="40px"> -->
				<img src="images/matadorgrouplogo.png" alt="Italian Trulli" height="70px">
				<br> <br>
				<div>
					<span class="login-text">Sales Management System</span><br> <span
						class="login-text-alt">Verification code send to your email address !!!
						</span>
						<br>
						<br>
						<span>Please input verification code</span>
						<br>
						<br>
						<span>${messageForgot} ${message}</span>
				</div>
			</div>
			<div class="login-square-container">
				<div class="login-square">
					<form action="PasswordChangeController" method="post" name="frmSave">
						<div class="input-container">
							<i class="fa fa-user icon"></i> <input class="input-field"
								type="text" readonly="readonly"  name="mobile" id="mobile" value="<%=mobile %>"  maxlength=30 size=40 required />
						</div>
						<div class="input-container">
							<i class="fa fa-lock icon"></i> <input class="input-field"
								type="text" placeholder="Verification Code" name="otp" id="otp" maxlength=10 size=40 required />
						</div>
						
						<div class="input-container">
							<i class="fa fa-key icon"></i> <input class="input-field"
								type="password" placeholder="New Password" name="newpassword" id="newpassword" maxlength=10 size=40 required />
						</div>
						
						<div class="input-container">
							<i class="fa fa-key icon"></i> <input class="input-field"
								type="password" placeholder="Confirm Password" name="conpassword" id="conpassword" maxlength=10 size=40 required />
						</div>
						
						<div class="input-container">
							<i class="fa fa-calendar-o icon"></i><input class="input-field"
								type="text" readonly="readonly"  name="updated" placeholder="YYYYMMDD" value="<%=strDate%>"  maxlength=14 size=40 />
						</div>
						
						<button class="btnblck" style="vertical-align: middle">
							<span>submit</span>
						</button>
						<input type="hidden" name="verificationCode" id="verificationCode" value="<%=verificationCode %>" />
					</form>
					<br> <br>
					<div class="forgot-password">
						<a href="${pageContext.request.contextPath}/forgetPassword.jsp"><span>Return</span></a>
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