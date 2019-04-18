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
	var id = document.getElementsByName('requisition_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/RequisitionController?action=edit&requisition_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/RequisitionController?action=delete&requisition_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/RequisitionController?action=enquiry&requisition_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/RequisitionController?action=cancel&requisition_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/RequisitionController?action=approve&requisition_id="+idValue;
	//for approve [E]
	
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/requisition.jsp">Requisition List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Requisition List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
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
				<th Class ="HeaderTH">Order Pack</th>
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
			<c:forEach items="${requisitions}" var="r"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="requisition_id" id="requisition_id" value="${r.requisition_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${r.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.customer_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${r.customer_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.mobile}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${r.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.bonus_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.bonus_name}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${r.order_pack}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.mrp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${r.total_mrp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.needed_date_time}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.to_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${r.salesman_id}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${r.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${r.order_status == 'P' ? 'Pending' : r.order_status == 'A' ? 'Approved' : r.order_status == 'C' ? 'Cancel' : r.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${r.delivery_status == 'P' ? 'Pending' : r.delivery_status == 'D' ? 'Delivered' : r.delivery_status == 'C' ? 'Cancel' : r.delivery_status == 'S' ? 'Success' : ''}" /></td>
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
					<a Class ="button" href="${pageContext.request.contextPath}/RequisitionController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
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