<%-- <jsp:include page="base.jsp"></jsp:include> --%>
<%
String action = (String) session.getAttribute("action");

if (action.equalsIgnoreCase("delete") || action.equalsIgnoreCase("cancel")) {
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
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
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
	
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseMainController?action=delete&purchase_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseMainController?action=enquiry&purchase_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseMainController?action=cancel&purchase_id="+idValue;
	//for cancel [E]
	
	if (idValue !=null) {
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
		//for cancel [S]
		document.getElementById('cancel').href = cancelPathWithIdValue;
		//for cancel [E]
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/customerPurchaseMain.jsp">Customer Purchase List</a></li>
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
				<th Class ="HeaderTH">Requisition ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<!-- <th Class ="HeaderTH">Customer ID</th> -->
				<th Class ="HeaderTH">Customer Name</th>
				<th Class ="HeaderTH">Mobile</th>
				<!-- <th Class ="HeaderTH">Needed Date</th>
				<th Class ="HeaderTH">From Account</th>
				<th Class ="HeaderTH">To Account</th>
				<th Class ="HeaderTH">Salesman ID</th> -->
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${customerPurchaseMains}" var="cpm"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="purchase_id" id="purchase_id" value="${cpm.purchase_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.purchase_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpm.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${cpm.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpm.customer_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpm.customer_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.mobile}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpm.needed_date_time}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.to_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.salesman_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpm.total_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpm.order_status == 'P' ? 'Pending' : cpm.order_status == 'A' ? 'Approved' : cpm.order_status == 'C' ? 'Cancel' : cpm.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpm.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpm.delivery_status == 'P' ? 'Pending' : cpm.delivery_status == 'D' ? 'Delivered' : cpm.delivery_status == 'C' ? 'Cancel' : cpm.delivery_status == 'S' ? 'Success' : cpm.delivery_status == 'R' ? 'Return' : ''}" /></td>
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
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
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