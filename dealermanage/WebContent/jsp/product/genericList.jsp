<%-- <jsp:include page="base.jsp"></jsp:include> --%>
<%
String action = (String) session.getAttribute("action");

if (action.equalsIgnoreCase("save") || action.equalsIgnoreCase("edit") || action.equalsIgnoreCase("delete")) {
%>
	<jsp:include page="../../base.jsp"></jsp:include>
<%
} else {
%>
	<jsp:include page="base.jsp"></jsp:include>
<%
}
%>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('generic_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/GenericController?action=edit&generic_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/GenericController?action=delete&generic_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/GenericController?action=enquiry&generic_id="+idValue;
	//for enquiry [E]
	
	if (idValue !=null) {
		//for update [S]
		document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
	} else {
		alert("Please select a Generic ID!!");
		return false;
	}
}

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/product/generic.jsp">Generic List</a></li>
					<li class="bread"><a href="">Dashboard > Product
							Management > Generic List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Generic ID</th>
				<th Class ="HeaderTH">Generic Name</th>
				<th Class ="HeaderTH">Product Category ID</th>
				<th Class ="HeaderTH">Indications</th>
				<th Class ="HeaderTH">Adult Dose</th>
				<!-- <th Class ="HeaderTH">Child Dose</th>
				<th Class ="HeaderTH">Renal Dose</th>
				<th Class ="HeaderTH">Administrations</th>
				<th Class ="HeaderTH">Contraindications</th>
				<th Class ="HeaderTH">Side Effects</th>
				<th Class ="HeaderTH">Precautions Warnings</th>
				<th Class ="HeaderTH">Pregnancy Category</th>
				<th Class ="HeaderTH">Therapeutic Class</th>
				<th Class ="HeaderTH">Mode of Action</th>
				<th Class ="HeaderTH">Interaction</th>
				<th Class ="HeaderTH">Created</th>
				<th Class ="HeaderTH">Updated</th> -->
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${generics}" var="g"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="generic_id" id="generic_id" value="${g.generic_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${g.generic_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.generic_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.product_category_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.indications}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.adult_dose}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${g.child_dose}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.renal_dose}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.administrations}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.contraindications}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.side_effects}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.precautions_warnings}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.pregnancy_category}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.therapeutic_class}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.mode_of_action}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.interaction}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.created}" /></td>
					<td Class ="FormInputColor"><c:out value="${g.updated}" /></td> --%>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a Class ="button" href="${pageContext.request.contextPath}/GenericController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a Class ="button" href="${pageContext.request.contextPath}/base.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>