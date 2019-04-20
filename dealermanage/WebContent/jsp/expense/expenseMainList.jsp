<%
String action = (String) session.getAttribute("action");

if (action.equalsIgnoreCase("approve") || action.equalsIgnoreCase("expenseApprove") || action.equalsIgnoreCase("expenseCancel")
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
	var id = document.getElementsByName('expense_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=edit&expense_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=delete&expense_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=enquiry&expense_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=cancel&expense_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=approve&expense_id="+idValue;
	//for approve [E]
	//for delivery approve [S]
	var expenseApprovePathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=expenseApprove&expense_id="+idValue;
	//for delivery approve [E]
	//for delivery return [S]
	var expenseCancelPathWithIdValue = "${pageContext.request.contextPath}/ExpenseMainController?action=expenseCancel&expense_id="+idValue;
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
		document.getElementById('expenseApprove').href = expenseApprovePathWithIdValue;
		//for delivery approve [E]
		//for delivery return [S]
		document.getElementById('expenseCancel').href = expenseCancelPathWithIdValue;
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/expense/expenseMain.jsp">Expense List</a></li>
					<li class="bread"><a href="">Dashboard > Expense 
							Management > Expense List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Expense ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<th Class ="HeaderTH">Owner Name</th>
				<th Class ="HeaderTH">Mobile</th>
				<th Class ="HeaderTH">From Account</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Expense Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${expenseMains}" var="em"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="expense_id" id="expense_id" value="${em.expense_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${em.expense_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${em.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${em.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<td Class ="FormInputColor"><c:out value="${em.owner_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${em.mobile}" /></td>
					<td Class ="FormInputColor"><c:out value="${em.from_account_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${em.total_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${em.order_status == 'P' ? 'Pending' : em.order_status == 'A' ? 'Approved' : em.order_status == 'C' ? 'Cancel' : em.order_status == 'S' ? 'Success' : ''}" /></td>
					<td Class ="FormInputColor"><c:out value="${em.expense_status == 'P' ? 'Pending' : em.expense_status == 'A' ? 'Approved' : em.expense_status == 'C' ? 'Cancel' : em.expense_status == 'S' ? 'Success' : em.expense_status == 'R' ? 'Return' : ''}" /></td>
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
					<a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="expenseApprove" Class ="button" href="" onclick="javascript: getRadioValue();">Expense Approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a id="expenseCancel" Class ="button" href="" onclick="javascript: getRadioValue();">Expense Cancel</a>
					<a Class ="button" href="${pageContext.request.contextPath}/base.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>