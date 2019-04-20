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
						<td class="PageHeader">Pack Pieces Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Pack Pieces Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Pack Pieces List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Pack Pieces Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Pack Pieces Update</td>
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
	<form action="PackPicecesController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>

			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Pack Pieces ID <span class="required">*</span></span>
				<%-- <input type="text" class="input-field" name="pack_piceces_id" id="pack_piceces_id" value="${packPiece.pack_piceces_id}"  maxlength=25 size=40 required /> --%>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field" readonly="readonly" name="pack_piceces_id" id="pack_piceces_id" value="${packPiecesId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Pack Pieces ID <span class="required">*</span></span>
				<input type="text" class="input-field" readonly="readonly" name="pack_piceces_id" id="pack_piceces_id" value="${packPiece.pack_piceces_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field2"><span>Pack Type <span class="required">*</span></span>
				<input type="text" class="input-field" name="pack_type" id="pack_type" value="${packPiece.pack_type}"  maxlength=40 size=40 required /> 
			</label> --%>
			<label for="field2"><span>Pack Type </span>
				<select name="pack_type" id="pack_type" class="select-field-30" >
					<option value="" >Select one</option>
					<option value="box" ${packPiece.pack_type == 'box' ? 'selected="selected"' : ''}>box</option>
					<option value="carton" ${packPiece.pack_type == 'carton' ? 'selected="selected"' : ''}>carton</option>
					<option value="bottle" ${packPiece.pack_type == 'bottle' ? 'selected="selected"' : ''}>bottle</option>
					<option value="strip" ${packPiece.pack_type == 'strip' ? 'selected="selected"' : ''}>strip</option>
				</select> 
			</label>
			
			<label for="field3"><span>Pack Size </span>
				<input type="text" class="input-field" name="pack_size" id="pack_size" value="${packPiece.pack_size}"  maxlength=25 size=40 /> 
			</label>
			
			<label for="field4"><span>Pieces </span>
				<input type="text" class="input-field" name="piceces" id="piceces" value="${packPiece.piceces}"  maxlength=10 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Created <span class="required">*</span></span>
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
			<label for="field5"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${packPiece.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="created" id="created" value="${packPiece.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field6"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${packPiece.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field" readonly="readonly" name="updated" id="updated" value="${packPiece.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field6"><span>Updated <span class="required">*</span></span>
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

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/packPiceces.jsp">Return</a>
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