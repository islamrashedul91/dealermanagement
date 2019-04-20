<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
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

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Expense Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Expense
							Management > Expense List > Expense Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Expense ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.expense_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Expense Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.expense_type}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseMain.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Owner ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.owner_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Owner Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.owner_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.mobile}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.needed_date_time}" /></td>
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.from_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.to_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Company ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.company_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Company Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.company_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.order_status == 'P' ? 'Pending' : expenseMain.order_status == 'A' ? 'Approved' : expenseMain.order_status == 'C' ? 'Cancel' : expenseMain.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Expense Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.expense_status == 'P' ? 'Pending' : expenseMain.expense_status == 'A' ? 'Approved' : expenseMain.expense_status == 'C' ? 'Cancel' : expenseMain.expense_status == 'S' ? 'Success' : expenseMain.expense_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseMain.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseMain.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseMain.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=expenseProductListEnquiry&expense_id=${expenseMain.expense_id}&date_time=${expenseMain.date_time}&owner_name=${expenseMain.owner_name}&mobile=${expenseMain.mobile}">Product Enquiry</a>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/expense/expenseMain.jsp">Return</a></td>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>