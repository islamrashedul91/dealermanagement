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
						<td class="PageHeader">Owner Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Owner Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Owner Profile > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Owner Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Owner Update</td>
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
	<form action="OwnerInfoController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Owner ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="owner_id" id="owner_id" value="${ownerId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Owner ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="owner_id" id="owner_id" value="${ownerInfo.owner_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Owner Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="owner_name" id="owner_name" value="${ownerInfo.owner_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field3"><span>Description </span>
				<input type="text" class="input-field-60" name="description" id="description" value="${ownerInfo.description}"  maxlength=100 size=40 /> 
			</label>
			
			<%-- <label for="field4"><span>Owner Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="owner_type" id="owner_type" value="${ownerInfo.owner_type}"  maxlength=25 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field11"><span>Owner Type </span>
				<select name="owner_type" id="owner_type" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="I">Individual</option>
					<option value="J">Join</option>
					<option value="O">Other</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field11"><span>Owner Type </span>
				<select name="owner_type" id="owner_type" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="I" ${ownerInfo.owner_type == 'I' ? 'selected="selected"' : ''}>Individual</option>
					<option value="J" ${ownerInfo.owner_type == 'J' ? 'selected="selected"' : ''}>Join</option>
					<option value="O" ${ownerInfo.owner_type == 'O' ? 'selected="selected"' : ''}>Other</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Owner Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="owner_start_date" id="owner_start_date" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field5"><span>Owner Since <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${ownerInfo.owner_start_date}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="owner_start_date" id="owner_start_date" value="${ownerInfo.owner_start_date}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field6"><span>Father Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="father_name" id="father_name" value="${ownerInfo.father_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Mother Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mother_name" id="mother_name" value="${ownerInfo.mother_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field8"><span>NID No. <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="nid" id="nid" value="${ownerInfo.nid}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field9"><span>Date of Birth <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="dob" id="dob" value="${ownerInfo.dob}" placeholder="yyyyMMdd"  maxlength=8 size=40 required /> 
			</label>
			
			<label for="field10"><span>Occupation </span>
				<input type="text" class="input-field-60" name="occupation" id="occupation" value="${ownerInfo.occupation}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field11"><span>Country Code <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="country_id" id="country_id" value="${ownerInfo.country_id}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field12"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mobile" id="mobile" value="${ownerInfo.mobile}"  maxlength=15 size=40 required /> 
			</label>
			
			<label for="field13"><span>Email </span>
				<input type="text" class="input-field-60" name="email" id="email" value="${ownerInfo.email}"  maxlength=200 size=40 required /> 
			</label>
			
			<%-- <label for="field14"><span>Account ID </span>
				<input type="text" class="input-field-60" name="account_id" id="account_id" value="${ownerInfo.account_id}"  maxlength=40 size=40 /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field7"><span>Account ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="account_id" id="account_id" value="${mainAccountId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field7"><span>Account ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="account_id" id="account_id" value="${ownerInfo.account_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field15"><span>Home Address <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="home_address" id="home_address" value="${ownerInfo.home_address}"  maxlength=200 size=40 required /> 
			</label>
			
			<label for="field16"><span>Office Address </span>
				<input type="text" class="input-field-60" name="office_address" id="office_address" value="${ownerInfo.office_address}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field17"><span>Profession <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="profession" id="profession" value="${ownerInfo.profession}"  maxlength=40 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field18"><span>Password <span class="required">*</span></span>
				<input type="password" class="input-field-60" name="password" id="password" value="${ownerInfo.password}"  maxlength=40 size=40 required /> 
			</label>
			<%
			}
			%>
			
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
					<option value="A" ${ownerInfo.status == 'A' ? 'selected="selected"' : ''}>Active</option>
					<option value="B" ${ownerInfo.status == 'B' ? 'selected="selected"' : ''}>Blocked</option>
					<option value="C" ${ownerInfo.status == 'C' ? 'selected="selected"' : ''}>Closed</option>
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
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${ownerInfo.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${ownerInfo.created}"  maxlength=14 size=40 required /> 
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
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${ownerInfo.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${ownerInfo.updated}"  maxlength=14 size=40 /> 
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

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/owner/ownerInfo.jsp">Return</a>
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