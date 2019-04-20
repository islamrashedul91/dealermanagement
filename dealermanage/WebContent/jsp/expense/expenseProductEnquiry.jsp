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
					<li class="title"><a href="">Expense Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Expense
							Management > Expense List > Expense Product List > Expense Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Expense Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.expense_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Expense ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.expense_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Expense Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.expense_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Expense Category ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.category_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Expense Category Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.category_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.quantity}" /></td>
				<td Class ="FormCellColor" colspan="2">Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.total_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.total_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.order_status == 'P' ? 'Pending' : expenseProduct.order_status == 'A' ? 'Approved' : expenseProduct.order_status == 'C' ? 'Cancel' : expenseProduct.order_status == 'S' ? 'Success' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Expense Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.expense_status == 'P' ? 'Pending' : expenseProduct.expense_status == 'A' ? 'Approved' : expenseProduct.expense_status == 'C' ? 'Cancel' : expenseProduct.expense_status == 'S' ? 'Success' : expenseProduct.expense_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${expenseProduct.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<%
						String action = (String) session.getAttribute("action");
						if (action.equalsIgnoreCase("enquiryEnquiry")) {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=expenseProductListEnquiry&expense_id=${expenseProduct.expense_id}&date_time=${expenseProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
						<%
						} else {
						%>
						<a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=return&expense_id=${expenseProduct.expense_id}&date_time=${expenseProduct.date_time}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
						<%
						}
						%>
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