<%-- <jsp:include page="base.jsp"></jsp:include> --%>
<%
String action = (String) session.getAttribute("action");

if (action.equalsIgnoreCase("approve") || action.equalsIgnoreCase("deliveryApprove") || action.equalsIgnoreCase("deliveryReturn")
		|| action.equalsIgnoreCase("delete") || action.equalsIgnoreCase("cancel")) {
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
	var id = document.getElementsByName('sales_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=edit&sales_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=delete&sales_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=enquiry&sales_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=cancel&sales_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=approve&sales_id="+idValue;
	//for approve [E]
	//for delivery approve [S]
	var deliveryApprovePathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=deliveryApprove&sales_id="+idValue;
	//for delivery approve [E]
	//for delivery return [S]
	var deliveryReturnPathWithIdValue = "${pageContext.request.contextPath}/SalesMainController?action=deliveryReturn&sales_id="+idValue;
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
		document.getElementById('deliveryApprove').href = deliveryApprovePathWithIdValue;
		//for delivery approve [E]
		//for delivery return [S]
		document.getElementById('deliveryReturn').href = deliveryReturnPathWithIdValue;
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/salesMain.jsp">Sales List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Sales List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Sales ID</th>
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
			<c:forEach items="${salesMains}" var="sm"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="sales_id" id="sales_id" value="${sm.sales_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.sales_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${sm.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${sm.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<%-- <td Class ="FormInputColor"><c:out value="${sm.customer_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${sm.customer_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.mobile}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${sm.needed_date_time}" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.to_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${sm.salesman_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${sm.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${sm.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${sm.order_status == 'P' ? 'Pending' : sm.order_status == 'A' ? 'Approved' : sm.order_status == 'C' ? 'Cancel' : sm.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${sm.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${sm.delivery_status == 'P' ? 'Pending' : sm.delivery_status == 'D' ? 'Delivered' : sm.delivery_status == 'C' ? 'Cancel' : sm.delivery_status == 'S' ? 'Success' : sm.delivery_status == 'R' ? 'Return' : ''}" /></td>
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
					<a Class ="button" href="${pageContext.request.contextPath}/SalesMainController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="deliveryApprove" Class ="button" href="" onclick="javascript: getRadioValue();">Delivery Approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a id="deliveryReturn" Class ="button" href="" onclick="javascript: getRadioValue();">Delivery Return</a>
					<a Class ="button" href="${pageContext.request.contextPath}/base.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>