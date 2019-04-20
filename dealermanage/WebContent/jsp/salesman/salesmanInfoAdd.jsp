<%-- <jsp:include page="base.jsp"></jsp:include> --%>
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
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Salesman Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Salesman Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Salesman List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Salesman Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Salesman Update</td>
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
	
	<form action="SalesmanInfoController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Salesman ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="salesman_id" id="salesman_id" value="${salesmanId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Salesman ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="salesman_id" id="salesman_id" value="${salesmanInfo.salesman_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Salesman Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="salesman_name" id="salesman_name" value="${salesmanInfo.salesman_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field3"><span>Salesman Description </span>
				<input type="text" class="input-field-60" name="salesman_desc" id="salesman_desc" value="${salesmanInfo.salesman_desc}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field4"><span>Salesman Type </span>
				<input type="text" class="input-field-60" name="salesman_type" id="salesman_type" value="${salesmanInfo.salesman_type}"  maxlength=40 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Salesman Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="salesman_start_date" id="salesman_start_date" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field5"><span>Salesman Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.salesman_start_date}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="salesman_start_date" id="salesman_start_date" value="${salesmanInfo.salesman_start_date}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field6"><span>Salesman Position </span>
				<input type="text" class="input-field-60" name="salesman_position" id="salesman_position" value="${salesmanInfo.salesman_position}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field7"><span>Father Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="father_name" id="father_name" value="${salesmanInfo.father_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field8"><span>Mother Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mother_name" id="mother_name" value="${salesmanInfo.mother_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field9"><span>NID No. <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="nid" id="nid" value="${salesmanInfo.nid}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field10"><span>Date of Birth <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="dob" id="dob" value="${salesmanInfo.dob}"  maxlength=25 size=40 required /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field11"><span>Occupation </span>
				<input type="text" class="input-field-60" name="occupation" id="occupation" value="${salesmanInfo.occupation}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field12"><span>Home Address <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="home_address" id="home_address" value="${salesmanInfo.home_address}"  maxlength=200 size=40 required /> 
			</label>
			
			<label for="field13"><span>Office Address </span>
				<input type="text" class="input-field-60" name="office_address" id="office_address" value="${salesmanInfo.office_address}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field14"><span>Country Code <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="country_id" id="country_id" value="${salesmanInfo.country_id}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field15"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mobile" id="mobile" value="${salesmanInfo.mobile}"  maxlength=15 size=40 required /> 
			</label>
			
			<label for="field16"><span>Email </span>
				<input type="text" class="input-field-60" name="email" id="email" value="${salesmanInfo.email}"  maxlength=200 size=40 /> 
			</label>
			
			<label for="field17"><span>Account ID </span>
				<input type="text" class="input-field-60" name="account_id" id="account_id" value="${salesmanInfo.account_id}"  maxlength=40 size=40 /> 
			</label>
			
			<%-- <label for="field19"><span>Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="status" id="status" value="${customerInfo.status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field18"><span>Status </span>
				<select name="status" id="status" class="select-field-60" >
					<option value="A">Active</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field18"><span>Status </span>
				<select name="status" id="status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="A" ${salesmanInfo.status == 'A' ? 'selected="selected"' : ''}>Active</option>
					<option value="R" ${salesmanInfo.status == 'R' ? 'selected="selected"' : ''}>Resigned</option>
					<option value="T" ${salesmanInfo.status == 'T' ? 'selected="selected"' : ''}>Terminated</option>
					<option value="I" ${salesmanInfo.status == 'I' ? 'selected="selected"' : ''}>Inactive</option>
					<option value="B" ${salesmanInfo.status == 'B' ? 'selected="selected"' : ''}>Blocked</option>
					<option value="C" ${salesmanInfo.status == 'C' ? 'selected="selected"' : ''}>Closed</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field19"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field19"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${salesmanInfo.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field20"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${salesmanInfo.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field20"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/salesman/salesmanInfo.jsp">Return</a>
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