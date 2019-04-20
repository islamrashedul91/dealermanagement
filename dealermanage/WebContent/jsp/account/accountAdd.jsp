<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">
</head>
<body>
<%
String action = (String) session.getAttribute("action");
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>
					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Account Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Account Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Account List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Account Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Account Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>	
	<form action="AccountController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>

			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Account ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field" readonly="readonly" name="account_id" id="account_id" value="${accountId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Account ID <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="account_id" id="account_id" value="${account.account_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field2"><span>Account Type <span class="required">*</span></span>
				<input type="text" class="input-field" name="account_type" id="account_type" value="${account.account_type}"  maxlength=25 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>Account Type </span>
				<select name="account_type" id="account_type" class="select-field-30" >
					<option value="MAIN">MAIN</option>
					<option value="CUSTOMER">CUSTOMER</option>
					<option value="SALESMAN">SALESMAN</option>
					<option value="OTHER">OTHER</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>Account Type </span>
				<select name="account_type" id="account_type" class="select-field-30" >
					<!-- <option value="" >Select one</option> -->
					<option value="MAIN" ${account.account_type == 'MAIN' ? 'selected="selected"' : ''}>MAIN</option>
					<option value="CUSTOMER" ${account.account_type == 'CUSTOMER' ? 'selected="selected"' : ''}>CUSTOMER</option>
					<option value="SALESMAN" ${account.account_type == 'SALESMAN' ? 'selected="selected"' : ''}>SALESMAN</option>
					<option value="OTHER" ${account.account_type == 'OTHER' ? 'selected="selected"' : ''}>OTHER</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<label for="field3"><span>Account Name <span class="required">*</span></span>
				<input type="text" class="input-field" name="account_name" id="account_name" value="${account.account_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field4"><span>Description </span>
				<input type="text" class="input-field" name="description" id="description" value="${account.description}"  maxlength=200 size=40 /> 
			</label>
			
			<label for="field5"><span>Previous Balance <span class="required">*</span></span>
				<input type="text" class="input-field" name="previous_balance" id="previous_balance" value="${account.previous_balance}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field6"><span>Current Balance <span class="required">*</span></span>
				<input type="text" class="input-field" name="current_balance" id="current_balance" value="${account.current_balance}"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field7"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="<%=strDate%>" maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field7"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${account.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}"/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="${account.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field8"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${account.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}"/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="${account.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field8"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}"/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/account/account.jsp">Return</a>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>