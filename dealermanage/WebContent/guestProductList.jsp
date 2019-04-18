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
	var id = document.getElementsByName('product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=edit&product_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=delete&product_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=enquiry&product_id="+idValue;
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
		alert("Please select a ID !!");
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/product/product.jsp">Product List</a></li>
					<li class="bread"><a href="">Dashboard > Product 
							Management > Product List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<!-- <th Class ="HeaderTH">Product Type ID</th> -->
				<!-- <th Class ="HeaderTH">Product Type</th>
				<th Class ="HeaderTH">Stength</th> -->
				<!-- <th Class ="HeaderTH">Brand ID</th>
				<th Class ="HeaderTH">Brand Name</th>
				<th Class ="HeaderTH">Company ID</th> -->
				<th Class ="HeaderTH">Company Name</th>
				<!-- <th Class ="HeaderTH">Product Category ID</th> -->
				<!-- <th Class ="HeaderTH">Product Category Name</th> -->
				<!-- <th Class ="HeaderTH">Generic ID</th> -->
				<th Class ="HeaderTH">Generic Name</th>
				<!-- <th Class ="HeaderTH">Pack Pieces ID</th>
				<th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">Rate Per Piece</th>
				<th Class ="HeaderTH">Rate Per Box</th> -->
				<!-- <th Class ="HeaderTH">TP</th> -->
				<th Class ="HeaderTH">MRP</th>
				<!-- <th Class ="HeaderTH">Total TP</th>
				<th Class ="HeaderTH">Total MRP</th> -->
				<!-- <th Class ="HeaderTH">Stock</th>
				<th Class ="HeaderTH">Bonus ID</th> -->
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${products}" var="p"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="product_id" id="product_id" value="${p.product_id}" onclick="javascript: getRadioValue();" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${p.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_type_id}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.stength}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.brand_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.brand_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.company_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${p.company_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_category_id}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_category_name}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.generic_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${p.generic_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.pack_piceces_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.rate_per_piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.rate_per_box}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.tp_price}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${p.mrp_price}" /> <br>Unit Price</td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.total_tp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.total_mrp_price}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${p.stock}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.bonus_id}" /></td> --%>
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
					<a Class ="button" href="${pageContext.request.contextPath}/ProductController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a Class ="button" href="${pageContext.request.contextPath}/load_modules.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>