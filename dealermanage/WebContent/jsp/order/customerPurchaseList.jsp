<jsp:include page="base.jsp"></jsp:include>
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
	var id = document.getElementsByName('purchase_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	//var updatePathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseController?action=edit&purchase_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseController?action=delete&purchase_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseController?action=enquiry&purchase_id="+idValue;
	//for enquiry [E]
	
	if (idValue !=null) {
		//for update [S]
		//document.getElementById('update').href = updatePathWithIdValue;
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/customerPurchase.jsp">Customer Purchase List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Customer Purchase List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Purchase ID</th>
				<!-- <th Class ="HeaderTH">Purchase Type</th> -->
				<th Class ="HeaderTH">Requisition ID</th>
				<!-- <th Class ="HeaderTH">Customer ID</th> -->
				<th Class ="HeaderTH">Customer Name</th>
				<th Class ="HeaderTH">Mobile</th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<!-- <th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">Bonus ID</th>
				<th Class ="HeaderTH">Bonus Name</th> -->
				<!-- <th Class ="HeaderTH">Order Pack</th> -->
				<th Class ="HeaderTH">Order Quantity</th>
				<th Class ="HeaderTH">MRP</th>
				<th Class ="HeaderTH">Total MRP</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<!-- <th Class ="HeaderTH">Needed Date</th>
				<th Class ="HeaderTH">From Account</th>
				<th Class ="HeaderTH">To Account</th>
				<th Class ="HeaderTH">Salesman ID</th> -->
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${customerPurchases}" var="cp"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="purchase_id" id="purchase_id" value="${cp.purchase_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.purchase_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.purchase_type}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.customer_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.customer_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.mobile}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.bonus_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.bonus_name}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.order_pack}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.mrp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${cp.total_mrp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.needed_date_time}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.to_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cp.salesman_id}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.order_status == 'P' ? 'Pending' : cp.order_status == 'A' ? 'Approved' : cp.order_status == 'C' ? 'Cancel' : cp.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cp.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cp.delivery_status == 'P' ? 'Pending' : cp.delivery_status == 'D' ? 'Delivered' : cp.delivery_status == 'C' ? 'Cancel' : cp.delivery_status == 'S' ? 'Success' : ''}" /></td>
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
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/CustomerPurchaseController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a> --%>
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