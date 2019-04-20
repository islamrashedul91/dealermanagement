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
						<td class="PageHeader">Expense Category Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Expense Category Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Expense Category List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Expense Category Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Expense Category Update</td>
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
	<form action="ExpenseCategoryController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>

			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Expense Category ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field" readonly="readonly" name="category_id" id="category_id" value="${expenseCategoryId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Expense Category ID <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="category_id" id="category_id" value="${expenseCategory.category_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Expense Category Name <span class="required">*</span></span>
				<input type="text" class="input-field" name="category_name" id="category_name" value="${expenseCategory.category_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field3"><span>Description </span>
				<input type="text" class="input-field" name="description" id="description" value="${expenseCategory.description}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field20"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field20"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseCategory.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="${expenseCategory.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field21"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseCategory.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="${expenseCategory.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field21"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/expense/expenseCategory.jsp">Return</a>
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