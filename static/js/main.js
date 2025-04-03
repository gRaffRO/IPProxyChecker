$('form').on('submit', function(e) {
    let count = 1;
    let textarea = $('textarea[name="multi_ip"]').val();
    let file = $('#file')[0].files[0];

    if (textarea) {
        count = textarea.trim().split("\n").filter(line => line.trim()).length;
    } else if (file) {
        let reader = new FileReader();
        reader.onload = function(e) {
            count = e.target.result.trim().split("\n").filter(line => line.trim()).length;
            startProgress(count);
        }
        reader.readAsText(file);
        return;
    }
    
    startProgress(count);
});

function startProgress(count) {
    $('#progress-container').show();
    $('#progress-count').text(`0 din ${count}`);
    let progress = 0;
    let interval = setInterval(() => {
        progress = Math.min(progress + 1, count);
        let percent = (progress / count) * 100;
        $('#progress-bar').css('width', percent + '%');
        $('#progress-count').text(`${progress} din ${count}`);
        
        if (progress >= count) {
            clearInterval(interval);
            $('.progress-text').html('Se procesează rezultatele...<br><small>Vă rugăm așteptați, acest proces poate dura câteva secunde.</small>');
        }
    }, 400);
}

$('#filterForm').on('submit', function(e) {
    e.preventDefault();
    downloadFilteredResults();
});

$('#showResults').on('click', function() {
    const formData = new FormData($('#filterForm')[0]);
    const params = new URLSearchParams();
    
    for (const [key, value] of formData.entries()) {
        params.append(key, value);
    }
    
    fetch(`/filter?${params.toString()}`)
        .then(response => response.text())
        .then(html => {
            $('#filtered-results .table-container').html(html);
            $('#filtered-results').show();
            if ($.fn.DataTable.isDataTable('#filtered-results table')) {
                $('#filtered-results table').DataTable().destroy();
            }
            $('#filtered-results table').DataTable({
                pageLength: 25,
                order: [[5, 'desc']],
                language: {
                    search: "Caută:",
                    lengthMenu: "Arată _MENU_ înregistrări per pagină",
                    info: "Afișare _START_ - _END_ din _TOTAL_ înregistrări",
                    paginate: {
                        first: "Prima",
                        last: "Ultima",
                        next: "Următoarea",
                        previous: "Precedenta"
                    }
                }
            });
        });
});

function downloadFilteredResults() {
    const formData = new FormData($('#filterForm')[0]);
    const params = new URLSearchParams();
    
    for (const [key, value] of formData.entries()) {
        params.append(key, value);
    }
    
    window.location.href = `/download?${params.toString()}`;
}

$(document).ready(function() {
    if ($('table').length) {
        $('table').DataTable({
            pageLength: 25,
            order: [[5, 'desc']],
            language: {
                search: "Caută:",
                lengthMenu: "Arată _MENU_ înregistrări per pagină",
                info: "Afișare _START_ - _END_ din _TOTAL_ înregistrări",
                paginate: {
                    first: "Prima",
                    last: "Ultima",
                    next: "Următoarea",
                    previous: "Precedenta"
                }
            }
        });
    }
});