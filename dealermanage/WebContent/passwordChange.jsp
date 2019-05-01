<%
if (session.getAttribute("username") == null)
	response.sendRedirect("login.jsp");
%>
<jsp:include page="base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>

<script language="JavaScript">
function doReturn() {
	document.frmSave.action="${pageContext.request.contextPath}/base.jsp";
	frmSave.submit();
}
</script>
		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Password Change</a></li>
					<li class="bread"><a href="">Dashboard > Password Change</a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
			<%
			String action = (String) session.getAttribute("action");
			//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
			SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
			Date date = new Date();  
			String strDate = formatter.format(date);			
			String mobile = (String)session.getAttribute("username");
			
			String message = (String)session.getAttribute("message");
			%>
			
			<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH" style="color:red;"><%=message %></th>
				</tr>
				<%
				}
				%>
			</table>
			<br>								
			<form action="PasswordChangeController" method="post" name="frmSave">
			
				<div class="form-style-2-heading">Provide your information</div>
				<label for="field1"><span>Mobile No. <span class="required">*</span></span> 
					<input type="text" class="input-field" readonly="readonly" name="mobile" id="mobile" value="<%=mobile %>"  maxlength=30 size=40 required /> 
				</label> 
				<label for="field2"><span>Current Password<span class="required">*</span></span> 
					<input type="password" class="input-field" name="password" id="password" value=""  maxlength=20 size=40 required />
				</label>
				<label for="field3"><span>New Password <span class="required">*</span></span> 
					<input type="password" class="input-field" name="newpassword" id="newpassword" value=""  maxlength=20 size=40 required /> 
				</label> 
				<label for="field4"><span>Confirm Password<span class="required">*</span></span> 
					<input type="password" class="input-field" name="conpassword" id="conpassword" value=""  maxlength=20 size=40 required />
				</label>
				 
				<label for="field5"><span>Password Change Date <span class="required">*</span></span> 
					<input type="text" class="input-field" readonly="readonly" name="updated" placeholder="YYYYMMDD" value="<%=strDate%>"  maxlength=14 size=40 /> 
				</label>  
				<label><span></span>
					<input type="submit" value="Submit" />
					<input name="but7" id="but7" type="button" value="Return" onClick="javascript:doReturn()">
				</label>
			</form>
			</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>
<br>