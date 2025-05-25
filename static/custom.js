// --- Add Livestock Form Validation ---
document.addEventListener('DOMContentLoaded', function() {
  var addForm = document.getElementById('addForm');
  if (addForm) {
    addForm.addEventListener('submit', function(event) {
      var valid = true;
      var farmer = document.getElementById('farmer');
      var type = document.getElementById('type');
      var quantity = document.getElementById('quantity');
      var date = document.getElementById('date');
      if (!farmer.value.trim()) {
        farmer.classList.add('is-invalid');
        valid = false;
      } else {
        farmer.classList.remove('is-invalid');
      }
      if (!type.value) {
        type.classList.add('is-invalid');
        valid = false;
      } else {
        type.classList.remove('is-invalid');
      }
      if (!quantity.value || parseInt(quantity.value) < 1) {
        quantity.classList.add('is-invalid');
        valid = false;
      } else {
        quantity.classList.remove('is-invalid');
      }
      if (!date.value) {
        date.classList.add('is-invalid');
        valid = false;
      } else {
        date.classList.remove('is-invalid');
      }
      if (!valid) {
        event.preventDefault();
        event.stopPropagation();
      }
    });
  }

  // --- Table Filtering (Verify/Remove Page) ---
  var filterInput = document.getElementById('filterInput');
  var tableBody = document.getElementById('tableBody');
  if (filterInput && tableBody) {
    filterInput.addEventListener('input', function() {
      var q = filterInput.value.trim();
      fetch('/api/livestock?q=' + encodeURIComponent(q))
        .then(response => response.json())
        .then(data => {
          tableBody.innerHTML = '';
          data.forEach(function(entry) {
            var tr = document.createElement('tr');
            tr.setAttribute('data-id', entry.id);
            tr.innerHTML = `
              <td>${entry.id}</td>
              <td>${entry.farmer}</td>
              <td>${entry.type}</td>
              <td>${entry.quantity}</td>
              <td>${entry.date}</td>
              <td>${entry.verified ? '<span class=\'badge badge-success\'>Yes</span>' : '<span class=\'badge badge-secondary\'>No</span>'}</td>
              <td>
                ${!entry.verified ? '<button class="btn btn-sm btn-success verify-btn">Verify</button>' : ''}
                <button class="btn btn-sm btn-danger remove-btn">Remove</button>
              </td>
            `;
            tableBody.appendChild(tr);
          });
        });
    });
  }

  // --- Verify/Remove Actions (AJAX) ---
  if (tableBody) {
    tableBody.addEventListener('click', function(event) {
      var target = event.target;
      var tr = target.closest('tr');
      if (!tr) return;
      var entryId = tr.getAttribute('data-id');
      if (target.classList.contains('verify-btn')) {
        fetch('/verify_action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'action=verify&id=' + encodeURIComponent(entryId)
        })
        .then(response => response.json())
        .then(data => { if (data.success) location.reload(); });
      }
      if (target.classList.contains('remove-btn')) {
        if (confirm('Are you sure you want to remove this entry?')) {
          fetch('/verify_action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=remove&id=' + encodeURIComponent(entryId)
          })
          .then(response => response.json())
          .then(data => { if (data.success) location.reload(); });
        }
      }
    });
  }
}); 