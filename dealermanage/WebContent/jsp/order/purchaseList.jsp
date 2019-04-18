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
	var updatePathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=edit&purchase_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=delete&purchase_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=enquiry&purchase_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=cancel&purchase_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=approve&purchase_id="+idValue;
	//for approve [E]
	//for delivery approve [S]
	var receiveApprovePathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=receiveApprove&purchase_id="+idValue;
	//for delivery approve [E]
	//for delivery return [S]
	var purchaseReturnPathWithIdValue = "${pageContext.request.contextPath}/PurchaseController?action=purchaseReturn&purchase_id="+idValue;
	//for delivery return [E]
	
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
		//for cancel [S]
		document.getElementById('cancel').href = cancelPathWithIdValue;
		//for cancel [E]
		//for approve [S]
		document.getElementById('approve').href = approvePathWithIdValue;
		//for approve [E]
		//for delivery approve [S]
		document.getElementById('receiveApprove').href = receiveApprovePathWithIdValue;
		//for delivery approve [E]
		//for delivery return [S]
		document.getElementById('purchaseReturn').href = purchaseReturnPathWithIdValue;
		//for delivery return [E]
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/purchase.jsp">Purchase List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Purchase List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Purchase ID</th>
				<th Class ="HeaderTH">Purchase Type</th>
				<th Class ="HeaderTH">Product Name</th>
				<th Class ="HeaderTH">Order Pack</th>
				<th Class ="HeaderTH">Order Quantity</th>
				<th Class ="HeaderTH">TP Price</th>
				<th Class ="HeaderTH">Total TP Price</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">From Account</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${purchases}" var="p"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="purchase_id" id="purchase_id" value="${p.purchase_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${p.purchase_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.purchase_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.product_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.order_pack}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.tp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${p.total_tp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.total_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.order_status == 'P' ? 'Pending' : p.order_status == 'A' ? 'Approved' : p.order_status == 'C' ? 'Cancel' : p.order_status == 'S' ? 'Success' : ''}" /></td>
					<td Class ="FormInputColor"><c:out value="${p.delivery_status == 'P' ? 'Pending' : p.delivery_status == 'D' ? 'Received' : p.delivery_status == 'C' ? 'Cancel' : p.delivery_status == 'R' ? 'Return' : ''}" /></td>
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
					<a Class ="button" href="${pageContext.request.contextPath}/PurchaseController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="receiveApprove" Class ="button" href="" onclick="javascript: getRadioValue();">Receive Approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a id="purchaseReturn" Class ="button" href="" onclick="javascript: getRadioValue();">Purchase Return</a>
					<a Class ="button" href="${pageContext.request.contextPath}/base.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>