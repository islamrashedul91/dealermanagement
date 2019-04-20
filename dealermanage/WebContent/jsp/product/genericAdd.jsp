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
						<td class="PageHeader">Generic Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Generic Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Product Management > Generic List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Generic Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Generic Update</td>
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
	<form action="GenericController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Generic ID <span class="required">*</span></span>
				<%-- <input type="text" class="input-field" name="generic_id" id="generic_id" value="${generic.generic_id}"  maxlength=25 size=40 required /> --%>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field" readonly="readonly" name="generic_id" id="generic_id" value="${genericId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Generic ID <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="generic_id" id="generic_id" value="${generic.generic_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Generic Name <span class="required">*</span></span>
				<input type="text" class="input-field" name="generic_name" id="generic_name" value="${generic.generic_name}"  maxlength=100 size=40 required /> 
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
					<%-- <option value="${generic.product_category_id}" selected>${generic.product_category_id}</option> --%>
					<c:forEach items="${allProductCategory}" var="apc">
						<option value="${apc.product_category_id}" ${apc.product_category_id == selectedProductCategoryId ? 'selected="selected"' : ''}>${apc.product_category_id}  -  ${apc.product_category_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field4"><span>Indications </span>
				<%-- <input type="text" class="input-field" name="indications" id="indications" value="${generic.indications}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="indications" id="indications" >${generic.indications}</textarea>
			</label>
			
			<label for="field5"><span>Adult Dose </span>
				<%-- <input type="text" class="input-field" name="adult_dose" id="adult_dose" value="${generic.adult_dose}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="adult_dose" id="adult_dose" >${generic.adult_dose}</textarea>
			</label>
			
			<label for="field6"><span>Child Dose </span>
				<%-- <input type="text" class="input-field" name="child_dose" id="child_dose" value="${generic.child_dose}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="child_dose" id="child_dose" >${generic.child_dose}</textarea>
			</label>
			
			<label for="field7"><span>Renal Dose </span>
				<%-- <input type="text" class="input-field" name="renal_dose" id="renal_dose" value="${generic.renal_dose}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="renal_dose" id="renal_dose" >${generic.renal_dose}</textarea>
			</label>
			
			<label for="field8"><span>Administrations </span>
				<%-- <input type="text" class="input-field" name="administrations" id="administrations" value="${generic.administrations}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="administrations" id="administrations" >${generic.administrations}</textarea>
			</label>
			
			<label for="field9"><span>Contraindications </span>
				<%-- <input type="text" class="input-field" name="contraindications" id="contraindications" value="${generic.contraindications}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="contraindications" id="contraindications" >${generic.contraindications}</textarea>
			</label>
			
			<label for="field10"><span>Side Effects </span>
				<%-- <input type="text" class="input-field" name="side_effects" id="side_effects" value="${generic.side_effects}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="side_effects" id="side_effects" >${generic.side_effects}</textarea>
			</label>
			
			<label for="field11"><span>Precautions Warnings </span>
				<%-- <input type="text" class="input-field" name="precautions_warnings" id="precautions_warnings" value="${generic.precautions_warnings}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="precautions_warnings" id="precautions_warnings" >${generic.precautions_warnings}</textarea>
			</label>
			
			<label for="field12"><span>Pregnancy Category </span>
				<%-- <input type="text" class="input-field" name="pregnancy_category" id="pregnancy_category" value="${generic.pregnancy_category}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="pregnancy_category" id="pregnancy_category" >${generic.pregnancy_category}</textarea>
			</label>
			
			<label for="field13"><span>Therapeutic Class </span>
				<%-- <input type="text" class="input-field" name="therapeutic_class" id="therapeutic_class" value="${generic.therapeutic_class}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="therapeutic_class" id="therapeutic_class" >${generic.therapeutic_class}</textarea>
			</label>
			
			<label for="field14"><span>Mode of Action </span>
				<%-- <input type="text" class="input-field" name="mode_of_action" id="mode_of_action" value="${generic.mode_of_action}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="mode_of_action" id="mode_of_action" >${generic.mode_of_action}</textarea>
			</label>
			
			<label for="field15"><span>Interaction </span>
				<%-- <input type="text" class="input-field" name="interaction" id="interaction" value="${generic.interaction}" size=40 /> --%> 
				<textarea rows="6" cols="43" class="input-field" name="interaction" id="interaction" >${generic.interaction}</textarea>
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
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${generic.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="${generic.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field17"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${generic.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="${generic.updated}"  maxlength=14 size=40 /> 
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

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/generic.jsp">Return</a>
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