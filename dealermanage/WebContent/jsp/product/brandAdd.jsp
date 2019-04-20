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

<script language="JavaScript">

function genericChng() {
	//document.getElementById('generic_name').value = document.getElementById('generic_id').value;
	oSelectOne = frmSave.elements["generic_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	//document.getElementById('generic_name').value = selected_option_text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('generic_name').value = finalText;

}

function companyChng() {
	oSelectOne = frmSave.elements["company_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('company_name').value = finalText;

}

</script>

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
						<td class="PageHeader">Brand Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Brand Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Product Management > Brand List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Brand Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Brand Update</td>
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
	<form action="BrandController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Brand ID <span class="required">*</span></span>
				<%-- <input type="text" class="input-field" name="brand_id" id="brand_id" value="${brand.brand_id}"  maxlength=25 size=40 required /> --%>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field" readonly="readonly" name="brand_id" id="brand_id" value="${brandId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Brand ID <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="brand_id" id="brand_id" value="${brand.brand_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Brand Name <span class="required">*</span></span>
				<input type="text" class="input-field" name="brand_name" id="brand_name" value="${brand.brand_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field8"><span>Company ID </span>
				<select name="company_id" id="company_id" class="select-field-30" onchange="companyChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCompany}" var="ac">
						<option value="${ac.company_id}">${ac.company_id}  -  ${ac.company_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field8"><span>Company ID </span>
				<select name="company_id" id="company_id" class="select-field-30" onchange="companyChng();" >
					<%-- <option value="${brand.company_id}" selected>${brand.company_id}</option> --%>
					<c:forEach items="${allCompany}" var="ac">
						<option value="${ac.company_id}" ${ac.company_id == selectedCompanyId ? 'selected="selected"' : ''}>${ac.company_id}  -  ${ac.company_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field9"><span>Company Name <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="company_name" id="company_name" value="${brand.company_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Product Category ID </span>
				<%-- <input type="text" class="input-field" name="product_category_id" id="product_category_id" value="${generic.product_category_id}"  maxlength=25 size=40 required /> --%>
				<select name="product_category_id" id="product_category_id" class="select-field-30">
					<option value="" >Select one</option>
					<c:forEach items="${allProductCategory}" var="apc">
						<option value="${apc.product_category_id}">${apc.product_category_id}  -  ${apc.product_category_name}</option>
					</c:forEach>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Product Category ID </span>
				<%-- <input type="text" class="input-field" name="product_category_id" id="product_category_id" value="${generic.product_category_id}"  maxlength=25 size=40 required /> --%> 
				<select name="product_category_id" id="product_category_id" class="select-field-30">
					<%-- <option value="${brand.product_category_id}" selected>${brand.product_category_id}</option> --%>
					<c:forEach items="${allProductCategory}" var="apc">
						<option value="${apc.product_category_id}" ${apc.product_category_id == selectedProductCategoryId ? 'selected="selected"' : ''}>${apc.product_category_id}  -  ${apc.product_category_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>Generic ID </span>
				<select name="generic_id" id="generic_id" class="select-field-30" onchange="genericChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allGeneric}" var="ag">
						<option value="${ag.generic_id}">${ag.generic_id}  -  ${ag.generic_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field4"><span>Generic ID </span>
				<select name="generic_id" id="generic_id" class="select-field-30" onchange="genericChng();" >
					<%-- <option value="${brand.generic_id}" selected>${brand.generic_id}</option> --%>
					<c:forEach items="${allGeneric}" var="ag">
						<option value="${ag.generic_id}" ${ag.generic_id == selectedGenericId ? 'selected="selected"' : ''}>${ag.generic_id}  -  ${ag.generic_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field5"><span>Generic Name <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="generic_name" id="generic_name" value="${brand.generic_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field16"><span>Created <span class="required">*</span></span>
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
			<label for="field16"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${brand.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="${brand.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field17"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${brand.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="${brand.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field17"><span>Updated <span class="required">*</span></span>
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

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/brand.jsp">Return</a>
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