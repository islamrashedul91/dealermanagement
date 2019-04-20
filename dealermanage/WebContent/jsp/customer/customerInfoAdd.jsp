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
					<!-- <li class="title"><a href="">Customer Add</a></li>
					<li class="bread"><a href="">Dashboard > Customer List > Customer Add</a></li> -->
					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Customer Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Customer Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Customer List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Customer Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Customer Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
/* String action = (String) session.getAttribute("action");
System.out.println("++++++"+action); */

//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>
	<%-- <table align="center">
				<tr>
				<%
				if (action.equalsIgnoreCase("save")) {
				%>
					<td class="PageHeader">Customer Add</td>
				<%
				} else if (action.equalsIgnoreCase("edit")) {
				%>
					<td class="PageHeader">Customer Update</td>
				<%
				}
				%>	
				</tr>
	</table>
	<br> --%>
	
	<form action="CustomerInfoController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Customer ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="customer_id" id="customer_id" value="${customerId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Customer ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="customer_id" id="customer_id" value="${customerInfo.customer_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Customer Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="customer_name" id="customer_name" value="${customerInfo.customer_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field3"><span>Customer Description </span>
				<input type="text" class="input-field-60" name="customer_desc" id="customer_desc" value="${customerInfo.customer_desc}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field4"><span>Customer Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="customer_type" id="customer_type" value="${customerInfo.customer_type}"  maxlength=25 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Customer Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="customer_start_date" id="customer_start_date" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field5"><span>Customer Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerInfo.customer_start_date}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="customer_start_date" id="customer_start_date" value="${customerInfo.customer_start_date}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field6"><span>Father Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="father_name" id="father_name" value="${customerInfo.father_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Mother Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mother_name" id="mother_name" value="${customerInfo.mother_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field8"><span>NID No. <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="nid" id="nid" value="${customerInfo.nid}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field9"><span>Date of Birth <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="dob" id="dob" value="${customerInfo.dob}" placeholder="yyyyMMdd"  maxlength=8 size=40 required /> 
			</label>
			
			<label for="field10"><span>Occupation </span>
				<input type="text" class="input-field-60" name="occupation" id="occupation" value="${customerInfo.occupation}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field11"><span>Country Code <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="country_id" id="country_id" value="${customerInfo.country_id}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field12"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mobile" id="mobile" value="${customerInfo.mobile}"  maxlength=15 size=40 required /> 
			</label>
			
			<label for="field13"><span>Email </span>
				<input type="text" class="input-field-60" name="email" id="email" value="${customerInfo.email}"  maxlength=200 size=40 required /> 
			</label>
			
			<label for="field14"><span>Account ID </span>
				<input type="text" class="input-field-60" name="account_id" id="account_id" value="${customerInfo.account_id}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field15"><span>Home Address <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="home_address" id="home_address" value="${customerInfo.home_address}"  maxlength=200 size=40 required /> 
			</label>
			
			<label for="field16"><span>Office Address </span>
				<input type="text" class="input-field-60" name="office_address" id="office_address" value="${customerInfo.office_address}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field17"><span>Profession <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="profession" id="profession" value="${customerInfo.profession}"  maxlength=40 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field18"><span>Password <span class="required">*</span></span>
				<input type="password" class="input-field-60" name="password" id="password" value="${customerInfo.password}"  maxlength=40 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field19"><span>Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="status" id="status" value="${customerInfo.status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field19"><span>Status </span>
				<select name="status" id="status" class="select-field-60" >
					<option value="A">Active</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field19"><span>Status </span>
				<select name="status" id="status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="A" ${customerInfo.status == 'A' ? 'selected="selected"' : ''}>Active</option>
					<option value="B" ${customerInfo.status == 'B' ? 'selected="selected"' : ''}>Blocked</option>
					<option value="C" ${customerInfo.status == 'C' ? 'selected="selected"' : ''}>Closed</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field20"><span>Created <span class="required">*</span></span>
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
			<label for="field20"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerInfo.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${customerInfo.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			</div>
			
			<div class="square-44">
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field21"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${customerInfo.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${customerInfo.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field21"><span>Updated <span class="required">*</span></span>
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

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/customer/customerInfo.jsp">Return</a>
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