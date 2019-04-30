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
String logginErrorMessage = (String) request.getAttribute("logginErrorMessage");
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
						class="login-text-alt">Please login to gain access to the
						system</span>
						<br>
						${logginErrorMessage}${messageForgot}
				</div>
			</div>
			<div class="login-square-container">
				<div class="login-square">
					<form action="LoginController" method="post">
						<div class="input-container">
							<i class="fa fa-user icon"></i> <input class="input-field"
								type="text" placeholder="mobile number" name="mobile" id="mobile" required>
						</div>
						<div class="input-container">
							<i class="fa fa-key icon"></i> <input class="input-field"
								type="password" placeholder="Password" name="password" id="password" required>
						</div>
						<button class="btnblck" style="vertical-align: middle">
							<span>Login</span>
						</button>
						<button type="reset" class="btnReset" style="vertical-align: middle">
							<span>Reset</span>
						</button>
					</form>
					<br> <br>
					<div class="forgot-password">
						<%-- <a href="${pageContext.request.contextPath}/passwordForget.jsp" target="_blank"><span>Forgot password?</span></a> --%>
						<a href="${pageContext.request.contextPath}/passwordForget.jsp"><span>Forgot password?</span></a>
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